//! SIP against a real, independent third-party client: **sipsak 0.9.8.1**.
//!
//! # Why this test exists
//!
//! `tests/server/sip/e2e_test.rs` hand-builds every request (`build_sip_register`,
//! `build_sip_options`, …) and checks the replies with the Wireshark `sip` dissector. That is
//! genuinely strong on *syntax* — an independent dissector parsing our bytes — but a dissector
//! does not run a transaction. It never asks whether the reply it just parsed would be
//! **accepted by the client that sent the request**, which in SIP is a separate question with
//! its own rules: the reply has to carry the request's `Via` back (branch and all), its
//! `Call-ID`, its `CSeq` and its `From` tag, or a real UA discards it and reports a timeout.
//!
//! sipsak is a C SIP torture-tester from the FhG Fokus SER lineage. It refuses a reply with no
//! `Via` (`the received message doesn't contain a Via header`) and one with no `CSeq`
//! (`'CSeq' not found in reply`), and it is what decides here whether our response matched.
//!
//! # Not circular
//!
//! `src/server/sip/` is a hand-written SIP implementation over `tokio::net::UdpSocket` with no
//! SIP library behind it — `Cargo.toml` says `sip = []`, no dependencies at all. sipsak is an
//! unrelated C binary on `PATH`.


use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;

/// Fail — never skip — when sipsak is missing.
fn require_sipsak() -> E2EResult<()> {
    match std::process::Command::new("sipsak")
        .arg("--version")
        .output()
    {
        Ok(out) => {
            let banner = String::from_utf8_lossy(&out.stdout);
            let banner = if banner.trim().is_empty() {
                String::from_utf8_lossy(&out.stderr).into_owned()
            } else {
                banner.into_owned()
            };
            println!(
                "sipsak present: {}",
                banner.lines().next().unwrap_or("(no banner)")
            );
            Ok(())
        }
        Err(e) => Err(format!(
            "sipsak not available ({e}): this test's whole point is driving a real SIP client \
             against NetGet's server, and skipping it would leave SIP's maturity rating \
             resting on our own hand-built requests. Install it with `brew install sipsak` \
             (or your distribution's sipsak package)."
        )
        .into()),
    }
}

/// Send one OPTIONS transaction with sipsak in shoot mode and return everything it printed.
///
/// `-vv` makes it dump the reply it accepted, which is what the assertions read. The wall-clock
/// bound matters because sipsak retransmits on its own timer when a server says nothing: a
/// server that answers *wrongly* does not fail this test, it hangs it.
async fn sipsak_options(port: u16, user: &str) -> E2EResult<(std::process::ExitStatus, String)> {
    let output = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new("sipsak")
            .arg("-vv")
            .arg("-s")
            .arg(format!("sip:{user}@127.0.0.1:{port}"))
            .output(),
    )
    .await
    .map_err(|_| format!("sipsak did not finish within 60s against 127.0.0.1:{port}"))??;

    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    println!("--- sipsak output ---\n{combined}\n--- end ---");
    Ok((output.status, combined))
}

#[tokio::test]
async fn test_sip_options_transaction_against_real_sipsak() -> E2EResult<()> {
    println!("\n=== E2E Test: sipsak OPTIONS against NetGet's SIP server ===");
    require_sipsak()?;

    let prompt = "listen on port {AVAILABLE_PORT} via sip. Answer OPTIONS with the methods we \
                  support";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock
            // sipsak's shoot mode sends OPTIONS; the server routes OPTIONS (and any unknown
            // method) to `sip_options`.
            //
            // Discriminate on `to`, NOT on `from`. sipsak's `From` is always
            // `sip:sipsak@<its own address>` — the user from `-s sip:USER@host` goes in the
            // Request-URI and the `To` header. Matching `from` here made the rule never fire,
            // the event fell through to a real LLM call, and the mock's 500 produced a
            // textbook `503 Service Unavailable` + `Retry-After: 5` — NetGet's documented
            // fail-closed reply, which sipsak accepted and parsed perfectly well. A wrong
            // mock that looks like a protocol bug is the most common mistake in this repo.
            .on_event("sip_options")
            .and_event_data_contains("to", "probe")
            .respond_with_actions(serde_json::json!([{
                "type": "sip_options",
                "status_code": 200,
                "reason_phrase": "OK",
                "allow_methods": ["INVITE", "ACK", "BYE", "REGISTER", "OPTIONS"]
            }]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("via sip")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SIP",
                    "instruction": "Answer OPTIONS with the methods we support"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    println!("SIP server on 127.0.0.1:{}", server.port);

    let (status, out) = sipsak_options(server.port, "probe").await?;

    // sipsak exits 0 only after accepting a final 2xx whose Via, Call-ID and CSeq it matched
    // against the request it sent. That correlation is the thing a dissector cannot check.
    assert!(
        status.success(),
        "sipsak rejected NetGet's 200 OK (exit {status}) — it did not accept the reply as \
         matching its own OPTIONS transaction:\n{out}"
    );
    assert!(
        out.contains("200") && out.to_uppercase().contains("OK"),
        "sipsak did not report a 200 OK final reply:\n{out}"
    );
    // The Allow header is built from the model's `allow_methods`, so seeing it in sipsak's
    // dump proves the action's own field reached the wire and survived a real parser.
    assert!(
        out.contains("Allow:"),
        "the Allow header built from allow_methods never reached sipsak:\n{out}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// REGISTER, the protocol's main admission decision, driven by the same real client.
///
/// OPTIONS is a capability query; REGISTER is the one that matters, and its metadata makes a
/// fail-closed claim (an LLM error is 503, a missing `status_code` is 500, never a defaulted
/// 200). This exercises the affirmative half of that against a real UA: sipsak's usrloc mode
/// sends a REGISTER with its own `Contact` and `Expires`, and accepts the 200 only if it
/// correlates.
#[tokio::test]
async fn test_sip_register_against_real_sipsak() -> E2EResult<()> {
    println!("\n=== E2E Test: sipsak REGISTER against NetGet's SIP server ===");
    require_sipsak()?;

    let prompt = "listen on port {AVAILABLE_PORT} via sip. Accept registrations for alice";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock
            // sipsak's usrloc mode registers and then de-registers, so more than one REGISTER
            // arrives. One rule answers them all with 200; `respond_with_actions_from_event`
            // keeps the answer tied to the event rather than hardcoding a second rule that
            // could never match (first-match-wins).
            .on_event("sip_register")
            .respond_with_actions_from_event(|_event| {
                serde_json::json!([{
                    "type": "sip_register",
                    "status_code": 200,
                    "reason_phrase": "OK",
                    "expires": 3600
                }])
            })
            .expect_calls(1)
            .and()
            .on_instruction_containing("via sip")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SIP",
                    "instruction": "Accept registrations for alice"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;

    let output = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new("sipsak")
            .arg("-vv")
            .arg("-U")
            .arg("-C")
            .arg(format!("sip:alice@127.0.0.1:{}", server.port))
            .arg("-s")
            .arg(format!("sip:alice@127.0.0.1:{}", server.port))
            .output(),
    )
    .await
    .map_err(|_| "sipsak did not finish within 60s")??;

    let mut out = String::from_utf8_lossy(&output.stdout).into_owned();
    out.push_str(&String::from_utf8_lossy(&output.stderr));
    println!("--- sipsak output ---\n{out}\n--- end ---");

    // sipsak's own verdict. It prints these only after accepting the response to its REGISTER
    // as a success; a non-2xx, a malformed reply or a timeout all produce a different summary
    // and a non-zero exit.
    //
    // Note what this test does NOT add: usrloc mode prints "Deactivated Via insertion in
    // usrloc mode", so sipsak is not checking Via correlation here. The correlation evidence
    // is the OPTIONS test above, where shoot mode does check it. This test's contribution is
    // that REGISTER — the admission decision, with its own fail-closed rules — is accepted by
    // a real UA when the model grants it.
    assert!(
        output.status.success(),
        "sipsak's REGISTER did not succeed (exit {}):\n{out}",
        output.status
    );
    assert!(
        out.contains("registering user alice"),
        "sipsak did not report registering alice:\n{out}"
    );
    assert!(
        out.contains("All usrloc tests completed successful."),
        "sipsak did not accept NetGet's REGISTER response:\n{out}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The refusal path, read back by the same real client.
///
/// A 403 and a 200 differ by three bytes on the status line and by nothing else structurally,
/// so this is what shows sipsak is reading our status code rather than merely receiving a
/// datagram — and that NetGet's refusal is a *correlated* SIP response rather than something a
/// UA would discard as unmatched.
#[tokio::test]
async fn test_sip_non_2xx_is_understood_by_real_sipsak() -> E2EResult<()> {
    println!("\n=== E2E Test: sipsak reads NetGet's 403 Forbidden ===");
    require_sipsak()?;

    let prompt = "listen on port {AVAILABLE_PORT} via sip. Refuse every request";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_event("sip_options")
            .respond_with_actions(serde_json::json!([{
                "type": "sip_options",
                "status_code": 403,
                "reason_phrase": "Forbidden"
            }]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("via sip")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "SIP",
                    "instruction": "Refuse every request"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    let (status, out) = sipsak_options(server.port, "denied").await?;

    assert!(
        out.contains("403"),
        "sipsak never reported the 403 status code NetGet sent:\n{out}"
    );
    // sipsak exits non-zero on a final non-2xx. A zero exit here would mean it had not read
    // our status line at all.
    assert!(
        !status.success(),
        "sipsak exited 0 for a 403 final reply, so it did not read the status code:\n{out}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

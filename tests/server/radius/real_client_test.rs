//! RADIUS against a real, independent client: FreeRADIUS `radclient`.
//!
//! Everything else in this directory is NetGet checking NetGet, or NetGet checking itself
//! against byte literals. This file is the only place a peer written by someone else decides
//! whether our packets are acceptable — and `radclient` is strict about the one thing that
//! matters most:
//!
//! ```text
//! Reply verification failed: Received Access-Accept packet from home server ...
//! with invalid Response Authenticator!  (Shared secret is incorrect.)
//! ```
//!
//! That was confirmed by hand against a deliberately-wrong authenticator before this test was
//! written, so a green run here really does mean the MD5 is right.
//!
//! **This test FAILS, it does not skip, when `radclient` is absent.** That is deliberate and
//! it is the whole reason RADIUS may be rated `Beta`. A skip-when-missing gate returns
//! `Ok(())` on a runner without FreeRADIUS, so the suite reports a silent pass and the
//! maturity rating ends up resting on nothing — which is exactly how a claim outlives the
//! evidence that justified it. `tests/server/npm/e2e_test.rs` is the precedent.
//!
//! Install with `brew install freeradius-server` (macOS) or `apt-get install -y freeradius-utils`
//! (Debian/Ubuntu). RADIUS is not in CI's `CI_FEATURES`, so this costs the CI gate nothing;
//! see `tests/server/radius/CLAUDE.md`.

use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Locate `radclient` — or fail the test, saying why a skip would be worse.
///
/// **Fail, never skip.** `radclient` is the only peer in this repository that NetGet did not
/// write, and it is the whole of RADIUS's `Beta` evidence. A machine without FreeRADIUS must
/// say so loudly rather than return `Ok(())`: a vacuous green is exactly how a maturity claim
/// outlives the thing that justified it, and `CLAUDE.md` names four protocols held back from
/// `Beta` for having precisely this gate. `tests/server/npm/e2e_test.rs` is the precedent.
///
/// This also confirms the binary *runs* rather than merely existing, so a broken or
/// architecture-mismatched install fails here with its own error rather than three assertions
/// later as an unexplained timeout.
async fn require_radclient() -> E2EResult<String> {
    let binary = find_radclient().ok_or_else(|| {
        "radclient not found (searched /opt/homebrew/bin, /usr/local/bin, /usr/bin and $PATH). \
         These two tests drive FreeRADIUS's own client against NetGet's RADIUS server, and \
         that is the only independent check that our Response Authenticator MD5 is right. \
         Skipping would leave RADIUS's Beta rating resting on nothing, so this is a failure \
         and not a skip. Install it with `brew install freeradius-server` (macOS) or \
         `apt-get install -y freeradius-utils` (Debian/Ubuntu). RADIUS is not in CI's \
         CI_FEATURES, so nothing in the CI gate compiles or runs this file."
            .to_string()
    })?;

    let version = Command::new(&binary)
        .arg("-v")
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| {
            format!(
                "`{binary} -v` could not be executed ({e}): a radclient that cannot run is not \
                 evidence of anything"
            )
        })?;

    // `radclient -v` exits non-zero on some builds while still printing its banner, so the
    // banner is what is asserted on rather than the exit status.
    let banner = format!(
        "{}{}",
        String::from_utf8_lossy(&version.stdout),
        String::from_utf8_lossy(&version.stderr)
    );
    if !banner.to_lowercase().contains("radclient") {
        return Err(format!(
            "`{binary} -v` printed no recognisable radclient banner, so this is not the \
             FreeRADIUS client these tests need:\n{banner}"
        )
        .into());
    }
    println!("radclient: {}", banner.lines().next().unwrap_or("").trim());

    Ok(binary)
}

/// Locate `radclient`, or `None` if FreeRADIUS is not installed here.
fn find_radclient() -> Option<String> {
    for candidate in [
        "/opt/homebrew/bin/radclient",
        "/usr/local/bin/radclient",
        "/usr/bin/radclient",
    ] {
        if std::path::Path::new(candidate).exists() {
            return Some(candidate.to_string());
        }
    }
    which_in_path("radclient")
}

fn which_in_path(binary: &str) -> Option<String> {
    let path = std::env::var("PATH").ok()?;
    for dir in path.split(':') {
        let candidate = std::path::Path::new(dir).join(binary);
        if candidate.exists() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

/// Run `radclient` against `port`, feeding it `attributes` on stdin.
/// Returns `(exit_ok, combined output)`.
async fn run_radclient(
    binary: &str,
    port: u16,
    attributes: &str,
    secret: &str,
) -> E2EResult<(bool, String)> {
    let mut child = Command::new(binary)
        .arg("-x") // print the decoded reply
        .arg("-t")
        .arg("5") // 5s per attempt
        .arg("-r")
        .arg("1") // one attempt: a retry would double the LLM calls
        .arg(format!("127.0.0.1:{}", port))
        .arg("auth")
        .arg(secret)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    child
        .stdin
        .as_mut()
        .ok_or("radclient stdin unavailable")?
        .write_all(format!("{}\n", attributes).as_bytes())
        .await?;
    drop(child.stdin.take());

    let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output()).await??;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok((output.status.success(), combined))
}

/// A grant, accepted by a client we did not write.
///
/// `radclient` verifies the Response Authenticator itself; if our MD5 were wrong it would
/// print "invalid Response Authenticator" and exit non-zero regardless of what the packet
/// said. It also decrypts nothing on our behalf — the fact that the mock's
/// event-derived branch fires proves the server unhid `User-Password` correctly.
#[tokio::test]
async fn freeradius_radclient_accepts_our_access_accept() -> E2EResult<()> {
    let binary = require_radclient().await?;

    let config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via radius with shared secret xyzzy5461. \
         Accept nemo when the password is arctangent.",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_event("radius_access_request")
            .respond_with_actions_from_event(|event| {
                let user = event["user_name"].as_str().unwrap_or("");
                let password = event["password"].as_str().unwrap_or("");
                if user == "nemo" && password == "arctangent" {
                    serde_json::json!([{
                        "type": "send_access_accept",
                        "reply_message": "Welcome nemo",
                        "framed_ip_address": "10.0.0.42",
                        "session_timeout": 3600
                    }])
                } else {
                    serde_json::json!([{
                        "type": "send_access_reject",
                        "reply_message": "Invalid credentials"
                    }])
                }
            })
            .expect_calls(1)
            .and()
            .on_instruction_containing("via radius")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "radius",
                "startup_params": {"shared_secret": "xyzzy5461"},
                "instruction": "Accept nemo/arctangent"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (ok, output) = run_radclient(
        &binary,
        server.port,
        "User-Name = nemo, User-Password = arctangent",
        "xyzzy5461",
    )
    .await?;

    println!("--- radclient ---\n{}", output);

    assert!(
        !output.contains("invalid Response Authenticator"),
        "radclient rejected our Response Authenticator — the MD5 over \
         (Code|ID|Length|RequestAuth|Attributes|Secret) is wrong.\n{}",
        output
    );
    assert!(
        output.contains("Received Access-Accept"),
        "radclient should have seen an Access-Accept.\n{}",
        output
    );
    assert!(
        output.contains("Welcome nemo"),
        "the model's Reply-Message must survive to a real client.\n{}",
        output
    );
    assert!(
        output.contains("10.0.0.42"),
        "radclient should decode the Framed-IP-Address the model assigned.\n{}",
        output
    );
    assert!(ok, "radclient exited non-zero.\n{}", output);

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// The fail-closed path, seen by a real client: no decision from the model must reach
/// `radclient` as an Access-Reject that still verifies.
///
/// A denial that a client discards as corrupt is not a denial — it is a timeout, and a NAS
/// configured to fail over would move to the next server and possibly get a yes.
#[tokio::test]
async fn freeradius_radclient_sees_a_valid_reject_when_the_model_is_silent() -> E2EResult<()> {
    let binary = require_radclient().await?;

    let config = NetGetConfig::new(
        "listen on port {AVAILABLE_PORT} via radius with shared secret xyzzy5461.",
    )
    .with_log_level("debug")
    .with_mock(|mock| {
        mock.on_event("radius_access_request")
            .respond_with_actions(serde_json::json!([]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("via radius")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "radius",
                "startup_params": {"shared_secret": "xyzzy5461"},
                "instruction": "Decide who may connect"
            }]))
            .expect_calls(1)
            .and()
    });

    let server = helpers::start_netget_server(config).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let (_ok, output) = run_radclient(
        &binary,
        server.port,
        "User-Name = nemo, User-Password = arctangent",
        "xyzzy5461",
    )
    .await?;

    println!("--- radclient ---\n{}", output);

    assert!(
        !output.contains("invalid Response Authenticator"),
        "the fail-closed reject must still be correctly signed.\n{}",
        output
    );
    assert!(
        output.contains("Received Access-Reject"),
        "a real client must see a denial, not a grant and not silence.\n{}",
        output
    );
    assert!(
        !output.contains("Received Access-Accept"),
        "an LLM that answered nothing MUST NOT produce an accept.\n{}",
        output
    );
    assert!(
        output.contains("Access denied: no authorization decision was produced"),
        "the reason must reach the client verbatim.\n{}",
        output
    );

    assert!(
        server
            .output_contains("decision=fail_closed_no_action")
            .await,
        "Output: {:?}",
        server.get_output().await
    );

    // Wait for the exchange the mocks describe, rather than trusting a fixed
    // sleep to have covered it. Under load the last event routinely lands after
    // the sleep expires, and the test reports it as never having happened.
    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

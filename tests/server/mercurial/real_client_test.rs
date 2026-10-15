//! Mercurial against the real `hg` client (7.2.4).
//!
//! # What this proves, and what it deliberately does not
//!
//! `tests/server/mercurial/e2e_test.rs` drives every path with `reqwest`, which the root
//! `CLAUDE.md` rules out as evidence on its own: a generic HTTP client proves an HTTP server
//! answered, not that the protocol layered on top is right. This test replaces the client with
//! the real thing for the one exchange the server can actually complete.
//!
//! `hg debugcapabilities <url>` runs Mercurial's **wire-protocol handshake**:
//! `httppeer.performhandshake` issues `?cmd=capabilities`, requires the reply to carry a
//! `Content-Type: application/mercurial-*` (`parsev1commandresponse`), and parses the
//! whitespace-separated capability list into a peer object. That is a real client applying real
//! protocol rules to our bytes — notably the content type, which no `reqwest` assertion in this
//! tree checks and which is the thing that makes `hg` treat us as a Mercurial repository at all
//! rather than as a web page.
//!
//! **It is not a clone, and it is not `hg id`, and those are not achievable against this
//! server.** See the module-level note in `real_client_ceiling` below — the reason is recorded
//! there because it is the reason this protocol is not promoted.
//!
//! # Not circular
//!
//! `src/server/mercurial/` is hand-written over NetGet's own HTTP layer and links no Mercurial
//! library (`Cargo.toml`: `mercurial = ["http", "urlencoding"]`). `hg` is a Python program.

use crate::server::helpers::{start_netget_server, E2EResult, NetGetConfig};
use std::time::Duration;

/// Why `hg clone` and `hg id` cannot be tested here, recorded where somebody will find it.
///
/// Measured against the installed `hg` 7.2.4:
///
/// * **`hg id`** aborts with `cannot look up remote revision; remote repository does not
///   support the 'lookup' capability` — after the capabilities request and before any second
///   request. `wireprotov1peer.lookup` begins `self.requirecap(b'lookup', …)`, and
///   `sanitize_capabilities` in `src/server/mercurial/actions.rs` **discards whatever the model
///   returns and substitutes the constant `["branchmap", "getbundle", "listkeys"]`**, so
///   `lookup` cannot be advertised at all. `?cmd=lookup` is also a 404.
/// * **`hg clone`** gets one step further and dies in discovery: because `getbundle` *is*
///   advertised, `setdiscovery.findcommonheads` issues `heads` **and `known`** — and `known` is
///   not capability-gated, so there is no way to opt out of being asked. NetGet 404s it.
///
/// So the protocol implements only the front of the wire protocol. That is the `openvpn`
/// situation the root `CLAUDE.md` describes: a real-client test that passes, is not ignored and
/// hard-fails when the binary is missing, and **still** does not justify Beta, because no real
/// client can use the server for the thing the protocol exists to do.
const fn real_client_ceiling() {}

/// Fail — never skip — when hg is missing.
fn require_hg() -> E2EResult<()> {
    real_client_ceiling();
    match std::process::Command::new("hg").arg("--version").output() {
        Ok(out) if out.status.success() => {
            println!(
                "{}",
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .next()
                    .unwrap_or("hg present")
            );
            Ok(())
        }
        Ok(out) => Err(format!(
            "`hg --version` exited {}: this test's whole point is driving the real Mercurial \
             client",
            out.status
        )
        .into()),
        Err(e) => Err(format!(
            "hg not available ({e}): this test's whole point is driving the real Mercurial \
             client against NetGet's server, and skipping it would leave Mercurial's evidence \
             resting on reqwest, which cannot tell a Mercurial repository from a web page. \
             Install it with `brew install mercurial` (or your distribution's mercurial \
             package)."
        )
        .into()),
    }
}

#[tokio::test]
async fn test_mercurial_handshake_against_real_hg_client() -> E2EResult<()> {
    println!("\n=== E2E Test: real `hg` performs the wire-protocol handshake ===");
    require_hg()?;

    let prompt = "listen on port {AVAILABLE_PORT} via mercurial. Serve the lab repository";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock
            // The model is deliberately asked for a GENEROUS list including capabilities the
            // server cannot honour. `sanitize_capabilities` must strip them back to the three
            // that are actually implemented, and the real client below must then see exactly
            // those three — which is the assertion that matters, because advertising `lookup`
            // or `unbundle` here would make `hg` issue a request that 404s.
            .on_event("hg_capabilities")
            .respond_with_actions(serde_json::json!([{
                "type": "hg_capabilities",
                "capabilities": [
                    "branchmap", "getbundle", "listkeys",
                    "lookup", "known", "batch", "unbundle", "pushkey"
                ]
            }]))
            .expect_calls(1)
            .and()
            .on_instruction_containing("via mercurial")
            .respond_with_actions(serde_json::json!([
                {
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "Mercurial",
                    "instruction": "Serve the lab repository"
                }
            ]))
            .expect_calls(1)
            .and()
    });

    let server = start_netget_server(config).await?;
    println!("Mercurial server on 127.0.0.1:{}", server.port);

    let url = format!("http://127.0.0.1:{}/lab", server.port);
    let output = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new("hg")
            .arg("debugcapabilities")
            .arg(&url)
            // Keep hg out of the invoking user's ~/.hgrc: an extension or a UI setting there
            // could change the output this test parses.
            .env("HGRCPATH", "")
            .env("HGPLAIN", "1")
            .output(),
    )
    .await
    .map_err(|_| "hg debugcapabilities did not finish within 60s")??;

    let mut out = String::from_utf8_lossy(&output.stdout).into_owned();
    out.push_str(&String::from_utf8_lossy(&output.stderr));
    println!("--- hg output ---\n{out}\n--- end ---");

    assert!(
        output.status.success(),
        "the real hg client could not complete the Mercurial handshake against NetGet (exit \
         {}). This is the exchange the server does implement, so a failure here is a protocol \
         bug rather than a missing feature:\n{out}",
        output.status
    );

    // hg only prints a capabilities block after `parsev1commandresponse` has accepted the
    // reply — which requires `Content-Type: application/mercurial-*`. A plain `text/plain`
    // body with identical bytes is rejected there, so this line is really an assertion about
    // the content type as much as about the list.
    assert!(
        out.contains("capabilities:"),
        "hg did not parse a capability list out of our response, so it did not accept us as a \
         Mercurial repository:\n{out}"
    );
    for advertised in ["branchmap", "getbundle", "listkeys"] {
        assert!(
            out.contains(advertised),
            "hg did not see the `{advertised}` capability:\n{out}"
        );
    }
    // The sanitiser's whole job, checked through a real client's parser rather than through a
    // string comparison on our own output. Advertising any of these would make hg issue a
    // request this server answers with a 404.
    for forbidden in ["lookup", "unbundle", "pushkey", "batch"] {
        assert!(
            !out.contains(forbidden),
            "hg saw the `{forbidden}` capability, which this server cannot honour — \
             sanitize_capabilities did not strip what the model asked for:\n{out}"
        );
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

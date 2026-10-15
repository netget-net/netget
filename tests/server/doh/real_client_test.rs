//! The real `kdig` binary — Knot DNS, a C implementation — against NetGet's DoH server.
//!
//! # Why this test exists
//!
//! `doh`'s Beta rating rested on `reqwest`, which is a genuinely independent HTTP/2 and TLS
//! implementation — and on **hickory-proto** for the DNS message, which is the codec this server
//! encodes with. So the transport half was proved and the DNS half was circular: it showed our
//! encoder agrees with our decoder. The protocol's own `e2e_testing` said exactly that.
//!
//! The root CLAUDE.md is blunt about the general form: a generic HTTP client "proves an HTTP
//! server answers, not that the protocol on top is right". reqwest is that generic client here.
//!
//! `kdig` is a DNS resolver that speaks RFC 8484 itself. It picks the transaction id, matches
//! the reply against it, confirms the question section, and renders the answer through its own
//! presentation writer — none of which our own codec can check on our behalf.
//!
//! # Both RFC 8484 encodings, by a client that chose them
//!
//! `+https` POSTs `application/dns-message`; `+https-get` sends `GET ?dns=<base64url>`. The
//! existing test covers both too, but with request bytes this repository built. Here the client
//! decides the framing, the base64url padding and the headers.
//!
//! Everything binds to 127.0.0.1. The certificate is self-signed and kdig's opportunistic
//! profile does not authenticate it, which is what lets this run without provisioning a CA —
//! and is also why certificate validation stays unproven.


use crate::helpers::{E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::process::Command;

/// Fail — never skip — when kdig is absent.
///
/// A `println!("SKIP")` + `return Ok(())` is a silent pass on any machine without the binary,
/// which is how a maturity claim outlives the evidence that justified it.
async fn require_kdig() -> E2EResult<String> {
    match Command::new("kdig").arg("-V").output().await {
        Ok(out) if out.status.success() => {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        }
        Ok(out) => Err(format!("`kdig -V` exited {}", out.status).into()),
        Err(e) => Err(format!(
            "kdig is not available ({e}): this test's whole point is driving a third-party DoH \
             client against NetGet's DoH server. Skipping would leave the DNS half of the \
             rating resting on hickory-proto, which is the codec the server itself encodes \
             with. `brew install knot` provides it."
        )
        .into()),
    }
}

struct KdigOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Run one kdig query over DoH. `get` selects `+https-get` instead of `+https`.
///
/// **`tokio::process`, not `std::process`.** `#[tokio::test]` runs a current-thread runtime, so
/// a blocking `output()` parks the only worker and stops the harness tasks draining the netget
/// child's pipes; the pipes fill, netget blocks inside a log call while serving, and the client
/// times out against a server that is perfectly correct.
async fn kdig_doh(port: u16, domain: &str, get: bool) -> KdigOutput {
    // The authority here becomes the HTTP `:authority` header **and the TLS SNI**, and it must
    // be a name rather than an IP literal: rustls rejects an IP address in SNI with a fatal
    // alert, which surfaces as `TLS, handshake failed (A TLS fatal alert has been received.)`
    // and looks exactly like a cipher or ALPN mismatch. `@127.0.0.1` still decides where the
    // connection goes, so nothing is resolved.
    // **Path only, no authority.** The authority half of `+https=[authority][/path]` becomes the
    // TLS SNI *and* switches kdig to a validating profile, and neither is wanted here: an IP
    // literal in SNI is rejected by rustls with a fatal alert, and a name makes kdig verify a
    // certificate that is self-signed by construction. Leaving it out keeps the opportunistic
    // profile that `+tls` uses, which is what the DoT test relies on too. `@127.0.0.1` decides
    // where the connection goes either way.
    let mode = if get {
        "+https-get=/dns-query".to_string()
    } else {
        "+https=/dns-query".to_string()
    };

    let out = Command::new("kdig")
        .arg(&mode)
        .arg("+timeout=20")
        .arg("+retry=0")
        .arg("-p")
        .arg(port.to_string())
        .arg("@127.0.0.1")
        .arg(domain)
        .arg("A")
        .output()
        .await
        .expect("failed to spawn kdig");

    KdigOutput {
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

/// One rule per event, branching on the event itself.
///
/// The query id is echoed from the event, which is not optional for a DNS-shaped protocol: a
/// resolver discards any reply whose id does not match, and kdig is a resolver. Two rules on one
/// event with nothing to tell them apart is the most common mocking mistake in this repo.
fn doh_server() -> NetGetConfig {
    NetGetConfig::new("Listen on port {AVAILABLE_PORT} via DoH. Answer A queries")
        .with_log_level("info")
        .with_mock(|mock| {
            mock.on_event("doh_query")
                .respond_with_actions_from_event(|event_data| {
                    // A distinct address per name, so an answer routed to the wrong question is
                    // visible rather than merely plausible.
                    let ip = match event_data["domain"].as_str().unwrap_or_default() {
                        d if d.starts_with("post.example.com") => "93.184.216.51",
                        d if d.starts_with("get.example.com") => "93.184.216.52",
                        _ => "93.184.216.34",
                    };
                    serde_json::json!([
                        {
                            "type": "send_dns_a_response",
                            "query_id": event_data["query_id"],
                            "domain": event_data["domain"],
                            "ip": ip,
                            "ttl": 300
                        }
                    ])
                })
                .expect_calls(2)
                .and()
                .on_instruction_containing("via DoH")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "DoH",
                    "instruction": "Answer A queries"
                }]))
                .expect_calls(1)
                .and()
        })
}

#[tokio::test]
async fn kdig_completes_both_rfc8484_encodings() -> E2EResult<()> {
    let version = require_kdig().await?;
    println!("kdig: {version}");

    let server = crate::server::helpers::start_netget_server(doh_server()).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    let port = server.port;

    // --- POST application/dns-message --------------------------------------
    let post = kdig_doh(port, "post.example.com", false).await;
    assert!(
        post.success,
        "kdig could not complete a DoH POST query.\nstdout: {}\nstderr: {}\n\nThis is the first \
         client other than hickory-proto to read this server's DNS replies, so a failure here \
         is about the wire, not about the test.",
        post.stdout, post.stderr
    );
    assert!(
        post.stdout.contains("93.184.216.51"),
        "kdig did not render the address we answered with over POST:\n{}",
        post.stdout
    );
    assert!(
        post.stdout.contains("post.example.com"),
        "kdig did not echo the queried name back out of the POST reply:\n{}",
        post.stdout
    );
    assert!(
        post.stdout.contains("NOERROR"),
        "kdig read a non-zero rcode out of the POST reply:\n{}",
        post.stdout
    );

    // --- GET ?dns=<base64url> ----------------------------------------------
    //
    // The other RFC 8484 encoding, and the one with a padding rule worth having a third party
    // apply: the query is base64url with padding stripped.
    let get = kdig_doh(port, "get.example.com", true).await;
    assert!(
        get.success,
        "kdig could not complete a DoH GET query.\nstdout: {}\nstderr: {}",
        get.stdout, get.stderr
    );
    assert!(
        get.stdout.contains("93.184.216.52"),
        "the GET query got the wrong answer, so replies are not bound to their questions:\n{}",
        get.stdout
    );
    assert!(
        !get.stdout.contains("93.184.216.51"),
        "the GET reply carried the POST query's address:\n{}",
        get.stdout
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

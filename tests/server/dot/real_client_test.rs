//! The real `kdig` binary — Knot DNS, a C implementation — against NetGet's DoT server.
//!
//! # Why this test exists
//!
//! `dot`'s Beta rating rested on `rustls` completing the handshake and on **hickory-proto**
//! assembling and decoding the DNS message. hickory-proto is the codec the server encodes with,
//! so that half was circular: the test proved our encoder agrees with our decoder. The
//! protocol's own `e2e_testing` said so, and named what would close it:
//!
//! > What is NOT proved: a third-party DoT client completing a session - kdig +tls
//! > (knot-dnsutils) is the one to reach for, and is not installed on this machine.
//!
//! It is installed now. This session has twice seen what a second, stricter client finds:
//! `etcd` and `grpc` were each Beta on one lenient peer, and in both cases **no conformant
//! implementation could complete a successful call** while every existing test passed.
//!
//! # What kdig checks that our own codec cannot
//!
//! kdig is a resolver, not a decoder. It matches the reply's transaction id against the one it
//! chose, checks the question section echoes what it asked, decodes the RFC 7858 two-byte length
//! prefix, and renders the answer through its own presentation-format writer. A reply that our
//! encoder and decoder happen to agree on but that is wrong on the wire fails here.
//!
//! Everything binds to 127.0.0.1; the certificate is self-signed, and plain `+tls` does not
//! authenticate it (validation needs `+tls-ca`, `+tls-hostname` or `+tls-pin`), which is what
//! lets the test run without provisioning a CA.


use crate::helpers::{E2EResult, NetGetConfig};
use std::time::Duration;
use tokio::process::Command;

/// Fail — never skip — when kdig is absent.
///
/// A `println!("SKIP")` + `return Ok(())` is a silent pass on any machine without the binary,
/// and that is exactly how a maturity claim outlives the evidence that justified it. The project
/// CLAUDE.md lists four protocols held at Experimental for this gate alone.
async fn require_kdig() -> E2EResult<String> {
    match Command::new("kdig").arg("-V").output().await {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            Ok(text.trim().to_string())
        }
        Ok(out) => Err(format!(
            "`kdig -V` exited {}: this test's whole point is driving a third-party DoT client",
            out.status
        )
        .into()),
        Err(e) => Err(format!(
            "kdig is not available ({e}): this test's whole point is driving a third-party DoT \
             client against NetGet's DoT server. Skipping would leave the rating resting on \
             hickory-proto, which is the codec the server itself encodes with — the circular \
             case this repository records for ssh/russh. `brew install knot` provides it."
        )
        .into()),
    }
}

struct KdigOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Run one `kdig +tls` query.
///
/// **`tokio::process`, not `std::process`.** `#[tokio::test]` runs a current-thread runtime, so
/// a blocking `output()` parks the only worker and stops the harness tasks draining the netget
/// child's stdout/stderr; the pipes fill, netget blocks inside a log call while serving, and the
/// client times out against a server that is perfectly correct.
async fn kdig(port: u16, domain: &str, rtype: &str) -> KdigOutput {
    let out = Command::new("kdig")
        .arg("+tls")
        .arg("+timeout=20")
        .arg("+retry=0")
        .arg("-p")
        .arg(port.to_string())
        .arg("@127.0.0.1")
        .arg(domain)
        .arg(rtype)
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
/// Two rules on the same event with no way to tell them apart is the most common mocking mistake
/// in this repo — the first answers every occurrence and the second reports zero calls. The
/// query id is echoed from the event, which is not optional for a DNS-shaped protocol: a
/// resolver discards any reply whose id does not match, and kdig is a resolver.
fn dot_server() -> NetGetConfig {
    NetGetConfig::new("Listen on port {AVAILABLE_PORT} via DoT. Answer A queries")
        .with_log_level("info")
        .with_mock(|mock| {
            mock.on_event("dot_query")
                .respond_with_actions_from_event(|event_data| {
                    // A distinct address per name, so an answer routed to the wrong question is
                    // visible rather than merely plausible.
                    let ip = match event_data["domain"].as_str().unwrap_or_default() {
                        d if d.starts_with("alpha.example.com") => "93.184.216.41",
                        d if d.starts_with("beta.example.com") => "93.184.216.42",
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
                .on_instruction_containing("via DoT")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "DoT",
                    "instruction": "Answer A queries"
                }]))
                .expect_calls(1)
                .and()
        })
}

#[tokio::test]
async fn kdig_completes_a_dot_query() -> E2EResult<()> {
    let version = require_kdig().await?;
    println!("kdig: {version}");

    let server = crate::server::helpers::start_netget_server(dot_server()).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    let port = server.port;

    // --- one query, decoded by a third-party resolver ----------------------
    let first = kdig(port, "alpha.example.com", "A").await;
    assert!(
        first.success,
        "kdig could not complete a DoT query.\nstdout: {}\nstderr: {}\n\nThis is the first time \
         a client other than hickory-proto has read this server's replies, so a failure here is \
         about the wire, not about the test.",
        first.stdout, first.stderr
    );

    // kdig prints the answer in presentation format only after matching the transaction id,
    // confirming the question section, and decoding the RFC 7858 length prefix.
    assert!(
        first.stdout.contains("93.184.216.41"),
        "kdig did not render the address we answered with:\n{}",
        first.stdout
    );
    assert!(
        first.stdout.contains("alpha.example.com"),
        "kdig did not echo the queried name back out of the reply:\n{}",
        first.stdout
    );
    assert!(
        first.stdout.contains("NOERROR"),
        "kdig read a non-zero rcode out of the reply:\n{}",
        first.stdout
    );

    // --- a second, different name ------------------------------------------
    //
    // One query cannot show an answer routed to the wrong question, because there is only one
    // question to route it to. The distinct address is what makes this assertion mean something.
    let second = kdig(port, "beta.example.com", "A").await;
    assert!(
        second.success,
        "the second kdig query failed.\nstdout: {}\nstderr: {}",
        second.stdout, second.stderr
    );
    assert!(
        second.stdout.contains("93.184.216.42"),
        "the second query got the wrong answer, so replies are not bound to their questions:\n{}",
        second.stdout
    );
    assert!(
        !second.stdout.contains("93.184.216.41"),
        "the second reply carried the first query's address:\n{}",
        second.stdout
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

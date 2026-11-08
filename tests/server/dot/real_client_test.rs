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
///
/// `keylog` is handed to kdig as `SSLKEYLOGFILE`, which GnuTLS honours, so the pcap oracle can
/// decrypt the session and read the DNS messages inside it.
async fn kdig(port: u16, domain: &str, rtype: &str, keylog: &std::path::Path) -> KdigOutput {
    let out = Command::new("kdig")
        .env("SSLKEYLOGFILE", keylog)
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
fn dot_server(queries: usize) -> NetGetConfig {
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
                    typed_answer(event_data).unwrap_or_else(|| {
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
                })
                .expect_calls(queries)
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

    let server = crate::server::helpers::start_netget_server(dot_server(2 + TYPED.len())).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    // kdig reaches the server through a recording relay and logs its TLS secrets, so the pcap
    // oracle at the end decrypts both sessions and reads the DNS inside them.
    let (relay, streams) = crate::helpers::recording_relay::tcp_relay(
        format!("127.0.0.1:{}", server.port).parse().unwrap(),
    )
    .await;
    let port = relay.port();
    let keys = tempfile::tempdir()?;
    let keylog = keys.path().join("sslkeylog.txt");

    // --- one query, decoded by a third-party resolver ----------------------
    let first = kdig(port, "alpha.example.com", "A", &keylog).await;
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
    let second = kdig(port, "beta.example.com", "A", &keylog).await;
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

    // --- every record type the actions write --------------------------------
    for (domain, rtype, expected) in TYPED {
        let out = kdig(port, domain, rtype, &keylog).await;
        assert_typed(
            out.success,
            &out.stdout,
            &out.stderr,
            domain,
            rtype,
            expected,
        );
    }

    // --- the pcap oracle, decrypted -----------------------------------------
    //
    // tshark decrypts each session with kdig's key log and hands the plaintext to its `dns`
    // dissector, which reads the RFC 7858 two-byte length prefix and the message behind it
    // independently of hickory-proto and of Knot. `require_named("dns")` is what makes this
    // a check on the server's DNS bytes rather than on the TLS record layer: without
    // decryption the chain stops at `tls` and the oracle fails. Port 853 is where tshark's
    // DNS dissector registers for TLS application data.
    let sessions = crate::helpers::recording_relay::recorded(&streams);
    assert!(
        sessions.len() >= 2,
        "both kdig sessions should have crossed the relay, saw {}",
        sessions.len()
    );
    for chunks in &sessions {
        crate::helpers::recording_relay::replay(
            crate::helpers::pcap_oracle::PcapOracle::tcp("dot")
                .port(853)
                .tls_keylog(&keylog)
                .require_named("dns"),
            chunks,
        )
        .assert_clean();
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// Fail — never skip — when dig is absent, for the reason [`require_kdig`] gives.
async fn require_dig() -> E2EResult<String> {
    match Command::new("dig").arg("-v").output().await {
        // `dig -v` prints its version on stderr.
        Ok(out) if out.status.success() => {
            Ok(String::from_utf8_lossy(&out.stderr).trim().to_string())
        }
        Ok(out) => Err(format!("`dig -v` exited {}", out.status).into()),
        Err(e) => Err(format!(
            "dig is not available ({e}): this test is the second independent DoT client — ISC \
             BIND's, beside Knot's kdig — and skipping it would leave the rating on one. BIND \
             9.18 or later is needed for `+tls` (`brew install bind`, `apt install \
             bind9-dnsutils`)."
        )
        .into()),
    }
}

/// One `dig +tls` query, with dig's defaults otherwise — EDNS and its COOKIE option included,
/// the way a person runs it. `+tries=1` keeps one query on the wire per call.
async fn dig_tls(port: u16, domain: &str, rtype: &str, keylog: &std::path::Path) -> KdigOutput {
    let out = Command::new("dig")
        .env("SSLKEYLOGFILE", keylog)
        .arg("+tls")
        .arg("+tries=1")
        .arg("+time=20")
        .arg("-p")
        .arg(port.to_string())
        .arg("@127.0.0.1")
        .arg(domain)
        .arg(rtype)
        .output()
        .await
        .expect("failed to spawn dig");
    KdigOutput {
        success: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).to_string(),
    }
}

/// The second independent DoT client: ISC BIND's `dig`, which shares no code with Knot's kdig,
/// with hickory or with rustls (it is C over OpenSSL). Like kdig it matches the transaction id
/// and the question before it prints an answer; unlike the kdig test it runs with EDNS on, so
/// it also reads the OPT record the server echoes back.
#[tokio::test]
async fn dig_completes_dot_queries_with_its_defaults() -> E2EResult<()> {
    let version = require_dig().await?;
    println!("dig: {version}");

    let server = crate::server::helpers::start_netget_server(dot_server(2 + TYPED.len())).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    // Direct, with no relay: BIND's dig writes no TLS key log (`SSLKEYLOGFILE` is honoured
    // by `named`'s logging, not by dig), so tshark could not decrypt its sessions. The oracle
    // runs over kdig's, which carry the same answers from the same server code.
    let port = server.port;
    let keys = tempfile::tempdir()?;
    let keylog = keys.path().join("unused-sslkeylog.txt");

    for (domain, ip, other) in [
        ("alpha.example.com", "93.184.216.41", "93.184.216.42"),
        ("beta.example.com", "93.184.216.42", "93.184.216.41"),
    ] {
        let out = dig_tls(port, domain, "A", &keylog).await;
        assert!(
            out.success && out.stdout.contains("status: NOERROR"),
            "dig +tls could not complete a DoT query for {domain}.\nstdout: {}\nstderr: {}",
            out.stdout,
            out.stderr
        );
        assert!(
            out.stdout.contains(ip) && !out.stdout.contains(other),
            "dig rendered the wrong address for {domain}:\n{}",
            out.stdout
        );
        // dig offered EDNS; RFC 6891 §6.1.1 has the server answer with an OPT of its own.
        assert!(
            out.stdout.contains("OPT PSEUDOSECTION"),
            "dig offered EDNS and the reply carried no OPT record:\n{}",
            out.stdout
        );
        assert!(
            !out.stdout.contains("WARNING") && !out.stdout.contains("malformed"),
            "dig reported a problem with the reply:\n{}",
            out.stdout
        );
    }

    for (domain, rtype, expected) in TYPED {
        let out = dig_tls(port, domain, rtype, &keylog).await;
        assert_typed(
            out.success,
            &out.stdout,
            &out.stderr,
            domain,
            rtype,
            expected,
        );
    }

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

/// Every record type the query actions write, beyond A: a name, the type asked for, and what
/// the resolver must print. The MX preference is 4660 (0x1234), so a byte-swap reads 13330
/// rather than something plausible — the DNS server's own Stable evidence uses the same value.
const TYPED: &[(&str, &str, &str)] = &[
    ("aaaa.example.com", "AAAA", "2001:db8::41"),
    ("mx.example.com", "MX", "4660 mail.example.com."),
    ("txt.example.com", "TXT", "\"netget-typed-txt\""),
    ("cname.example.com", "CNAME", "www.example.com."),
    ("nx.example.com", "A", "NXDOMAIN"),
];

/// The answer for a [`TYPED`] name, or `None` for every other name.
fn typed_answer(event: &serde_json::Value) -> Option<serde_json::Value> {
    let domain = event["domain"].as_str().unwrap_or_default();
    let base = |kind: &str| serde_json::json!({"type": kind, "query_id": event["query_id"], "domain": event["domain"], "ttl": 300});
    let mut action = match domain.trim_end_matches('.') {
        "aaaa.example.com" => {
            let mut a = base("send_dns_aaaa_response");
            a["ip"] = "2001:db8::41".into();
            a
        }
        "mx.example.com" => {
            let mut a = base("send_dns_mx_response");
            a["exchange"] = "mail.example.com".into();
            a["preference"] = 4660.into();
            a
        }
        "txt.example.com" => {
            let mut a = base("send_dns_txt_response");
            a["text"] = "netget-typed-txt".into();
            a
        }
        "cname.example.com" => {
            let mut a = base("send_dns_cname_response");
            a["target"] = "www.example.com".into();
            a
        }
        "nx.example.com" => {
            let mut a = base("send_dns_nxdomain");
            a["query_type"] = "A".into();
            a
        }
        _ => return None,
    };
    if action["type"] == "send_dns_nxdomain" {
        action.as_object_mut().map(|o| o.remove("ttl"));
    }
    Some(serde_json::json!([action]))
}

fn assert_typed(
    success: bool,
    stdout: &str,
    stderr: &str,
    domain: &str,
    rtype: &str,
    expected: &str,
) {
    assert!(
        success,
        "the resolver could not complete the {rtype} query for {domain}.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains(expected),
        "the {rtype} answer for {domain} did not render as {expected:?}:\n{stdout}"
    );
    if expected != "NXDOMAIN" {
        assert!(
            stdout.contains("NOERROR"),
            "the {rtype} answer for {domain} carried a non-zero rcode:\n{stdout}"
        );
    }
}

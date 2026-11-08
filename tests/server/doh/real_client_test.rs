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
///
/// `keylog` is handed to kdig as `SSLKEYLOGFILE`, which GnuTLS honours, so the pcap oracle can
/// decrypt the session and read the HTTP/2 and DNS inside it.
async fn kdig_doh(port: u16, domain: &str, get: bool, keylog: &std::path::Path) -> KdigOutput {
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
        .env("SSLKEYLOGFILE", keylog)
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
fn doh_server(queries: usize) -> NetGetConfig {
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

    let server = crate::server::helpers::start_netget_server(doh_server(2 + TYPED.len())).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    // kdig reaches the server through a recording relay and logs its TLS secrets, so the pcap
    // oracle at the end decrypts both sessions and reads the HTTP/2 and DNS inside them.
    let (relay, streams) = crate::helpers::recording_relay::tcp_relay(
        format!("127.0.0.1:{}", server.port).parse().unwrap(),
    )
    .await;
    let port = relay.port();
    let keys = tempfile::tempdir()?;
    let keylog = keys.path().join("sslkeylog.txt");

    // --- POST application/dns-message --------------------------------------
    let post = kdig_doh(port, "post.example.com", false, &keylog).await;
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
    let get = kdig_doh(port, "get.example.com", true, &keylog).await;
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

    // --- every record type the actions write, over POST ---------------------
    for (domain, rtype, expected) in TYPED {
        let out = kdig_doh_typed(port, domain, rtype, &keylog).await;
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
    // tshark decrypts each session with kdig's key log; ALPN `h2` hands the plaintext to its
    // `http2` dissector, and the `application/dns-message` body to `dns` — HPACK, framing,
    // flow control and the DNS reply all read independently of hyper, h2 and hickory-proto.
    // `require_named("dns")` is what makes this a check on the server's DNS bytes rather than
    // on the TLS record layer: without decryption the chain stops at `tls` and this fails.
    let sessions = crate::helpers::recording_relay::recorded(&streams);
    assert!(
        sessions.len() >= 2,
        "both kdig sessions should have crossed the relay, saw {}",
        sessions.len()
    );
    for chunks in &sessions {
        crate::helpers::recording_relay::replay(
            crate::helpers::pcap_oracle::PcapOracle::tcp("doh")
                .port(443)
                .tls_keylog(&keylog)
                .require_named("http2")
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
            "dig is not available ({e}): this test is the second independent DoH client — ISC \
             BIND's, beside Knot's kdig — and skipping it would leave the rating on one. BIND \
             9.18 or later is needed for `+https` (`brew install bind`, `apt install \
             bind9-dnsutils`)."
        )
        .into()),
    }
}

/// One `dig +https` (POST) or `+https-get` query with dig's defaults otherwise: EDNS and its
/// COOKIE option on, the way a person runs it. `+tries=1` keeps one query on the wire per call.
async fn dig_doh(
    port: u16,
    domain: &str,
    rtype: &str,
    get: bool,
    keylog: &std::path::Path,
) -> KdigOutput {
    let out = Command::new("dig")
        .env("SSLKEYLOGFILE", keylog)
        .arg(if get { "+https-get" } else { "+https" })
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

/// The second independent DoH client: ISC BIND's `dig`, C over OpenSSL and nghttp2, sharing no
/// code with Knot's kdig (GnuTLS, its own HTTP/2 via libnghttp2 too, but its own DNS stack), with
/// hyper, h2, rustls or hickory. Both RFC 8484 encodings, EDNS on.
#[tokio::test]
async fn dig_completes_both_rfc8484_encodings_with_its_defaults() -> E2EResult<()> {
    let version = require_dig().await?;
    println!("dig: {version}");

    let server = crate::server::helpers::start_netget_server(doh_server(2 + TYPED.len())).await?;
    crate::helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    // Direct, with no relay: BIND's dig writes no TLS key log (`SSLKEYLOGFILE` is honoured
    // by `named`'s logging, not by dig), so tshark could not decrypt its sessions. The oracle
    // runs over kdig's, which carry the same answers from the same server code.
    let port = server.port;
    let keys = tempfile::tempdir()?;
    let keylog = keys.path().join("unused-sslkeylog.txt");

    for (domain, get, ip, other) in [
        ("post.example.com", false, "93.184.216.51", "93.184.216.52"),
        ("get.example.com", true, "93.184.216.52", "93.184.216.51"),
    ] {
        let out = dig_doh(port, domain, "A", get, &keylog).await;
        assert!(
            out.success && out.stdout.contains("status: NOERROR"),
            "dig could not complete a DoH {} query for {domain}.\nstdout: {}\nstderr: {}",
            if get { "GET" } else { "POST" },
            out.stdout,
            out.stderr
        );
        assert!(
            out.stdout.contains(ip) && !out.stdout.contains(other),
            "dig rendered the wrong address for {domain}:\n{}",
            out.stdout
        );
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
        let out = dig_doh(port, domain, rtype, false, &keylog).await;
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

/// `kdig +https` for one name and record type, POST.
async fn kdig_doh_typed(
    port: u16,
    domain: &str,
    rtype: &str,
    keylog: &std::path::Path,
) -> KdigOutput {
    let out = Command::new("kdig")
        .env("SSLKEYLOGFILE", keylog)
        .arg("+https=/dns-query")
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

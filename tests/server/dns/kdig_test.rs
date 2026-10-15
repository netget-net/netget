//! The DNS server, driven by `kdig` — a second resolver, from a different project than `dig`.
//!
//! # Why a second one
//!
//! `dig_test.rs` already breaks the circularity that `test.rs` has: the server encodes with
//! hickory-proto and `test.rs` decodes with hickory-client, so that suite proves the wire format
//! is self-consistent rather than correct. ISC's `dig` shares no code with hickory and fixed it.
//!
//! One client is still one client, and this session has twice shown what the second one finds.
//! `etcd` and `grpc` were each Beta on a single lenient peer, and in both cases **no conformant
//! implementation could complete a successful call** while every existing test passed. The
//! project CLAUDE.md's bar for `Stable` asks for two independent third-party clients for exactly
//! that reason, and `dns` is one of the few protocols close enough for the second to be cheap.
//!
//! `kdig` is Knot DNS's resolver — CZ.NIC, not ISC, and a separate implementation of the same
//! RFCs. Two resolvers that agree with each other and with us is the strongest evidence short of
//! the spec; two that disagree is a finding.
//!
//! # What it checks that a round-trip cannot
//!
//! Like dig, kdig picks the transaction id and discards a reply that does not carry it back,
//! confirms the question section, and reports the RCODE. Unlike dig it renders through its own
//! presentation writer, so the rdata assertions here are a second independent reading of the
//! same bytes.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use tokio::process::Command;

/// Fail — never skip — when kdig is absent.
///
/// A `println!("SKIP")` + `return Ok(())` is a silent pass on any machine without the binary,
/// which is how `kubernetes`, `oci_registry`, `maven` and `websocket` ended up with maturity
/// ratings resting on nothing.
async fn require_kdig() -> E2EResult<String> {
    match Command::new("kdig").arg("-V").output().await {
        Ok(out) if out.status.success() => {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
        }
        Ok(out) => Err(format!("`kdig -V` exited {}", out.status).into()),
        Err(e) => Err(format!(
            "kdig is not available ({e}): this test exists to put a SECOND independent resolver \
             on this server, because one client can agree with one bug. `brew install knot` \
             provides it; the Debian/Ubuntu package is knot-dnsutils."
        )
        .into()),
    }
}

/// Run one `kdig` query over UDP.
///
/// `+retry=0` keeps exactly one query on the wire per call, so `expect_calls` means what it
/// says — a retry is another `dns_query` event and another mock call.
///
/// `+noedns` because this server does not implement EDNS0: the OPT record in a query is ignored
/// and none is added to replies (`src/server/dns/CLAUDE.md`). A resolver that offers EDNS and
/// gets a reply with no OPT record may fall back and re-query, which would be a second event.
///
/// **`tokio::process::Command`, never `std::process::Command`.** Each `#[tokio::test]` runs on a
/// current-thread runtime and the mock model is in-process on that same runtime, so a blocking
/// `output()` parks the very executor that has to answer the `dns_query` event. The symptom is
/// the client timing out against a server that is up and listening, which is indistinguishable
/// from a broken server and is neither. `dig_test.rs` records the same trap at length.
async fn kdig(port: u16, args: &[&str]) -> E2EResult<String> {
    let port_arg = port.to_string();
    let mut argv: Vec<&str> = vec![
        "@127.0.0.1",
        "-p",
        &port_arg,
        "+retry=0",
        "+timeout=5",
        "+noedns",
        "+notcp",
    ];
    argv.extend_from_slice(args);

    let out = Command::new("kdig").args(&argv).output().await?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();

    if !out.status.success() {
        // Printed as well as returned: the harness's `Drop` panics on an unverified mock before
        // a returned `Err` is rendered, so without this the only visible symptom is
        // "expected 1, got 0" — which says the server was never asked and not why.
        eprintln!(
            "kdig {} exited {}\nstdout:\n{}\nstderr:\n{}",
            argv.join(" "),
            out.status,
            stdout,
            String::from_utf8_lossy(&out.stderr)
        );
        return Err(format!("kdig {} exited {}", argv.join(" "), out.status).into());
    }
    Ok(stdout)
}

/// One server, six queries: A, TXT, AAAA, MX, CNAME, and a name that does not exist.
///
/// Bundled onto one server because each spawn costs an extra startup call and several seconds.
#[tokio::test]
async fn test_dns_answers_kdig() -> E2EResult<()> {
    let version = require_kdig().await?;
    println!("\n=== E2E Test: DNS answered by Knot kdig ===\n{version}");

    let prompt = "listen on port {AVAILABLE_PORT} via dns. Resolve kdig.example.com to \
                  93.184.216.44, answer TXT for kdig.example.com, NXDOMAIN everything else";

    let server_config = NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // Most specific first: `and_event_data_contains` is a substring match, and
                // "kdig.example.com" is a substring of "missing.kdig.example.com".
                .on_event("dns_query")
                .and_event_data_contains("domain", "missing.kdig.example.com")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_dns_nxdomain",
                        "query_id": event["query_id"],
                        "domain": event["domain"]
                    }])
                })
                .expect_calls(1)
                .and()
                .on_event("dns_query")
                .and_event_data_contains("query_type", "TXT")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_dns_txt_response",
                        "query_id": event["query_id"],
                        "domain": event["domain"],
                        "text": "answered-by-netget",
                        "ttl": 300
                    }])
                })
                .expect_calls(1)
                .and()
                .on_event("dns_query")
                .and_event_data_contains("query_type", "AAAA")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_dns_aaaa_response",
                        "query_id": event["query_id"],
                        "domain": event["domain"],
                        "ip": "2001:db8::2c",
                        "ttl": 300
                    }])
                })
                .expect_calls(1)
                .and()
                .on_event("dns_query")
                .and_event_data_contains("query_type", "MX")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_dns_mx_response",
                        "query_id": event["query_id"],
                        "domain": event["domain"],
                        "exchange": "mail.kdig.example.com.",
                        "preference": 4660,
                        "ttl": 300
                    }])
                })
                .expect_calls(1)
                .and()
                .on_event("dns_query")
                .and_event_data_contains("query_type", "CNAME")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_dns_cname_response",
                        "query_id": event["query_id"],
                        "domain": event["domain"],
                        "target": "www.kdig.example.com.",
                        "ttl": 300
                    }])
                })
                .expect_calls(1)
                .and()
                .on_event("dns_query")
                .and_event_data_contains("domain", "kdig.example.com")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_dns_a_response",
                        "query_id": event["query_id"],
                        "domain": event["domain"],
                        "ip": "93.184.216.44",
                        "ttl": 300
                    }])
                })
                .expect_calls(1)
                .and()
                .on_instruction_containing("via dns")
                .respond_with_actions(serde_json::json!([{
                    "type": "open_server",
                    "port": 0,
                    "base_stack": "DNS",
                    "instruction": "Answer queries"
                }]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(server_config).await?;
    helpers::wait_for_server_listening(&server, std::time::Duration::from_secs(30)).await?;
    let port = server.port;

    // --- A record ----------------------------------------------------------
    //
    // kdig prints the answer only after matching the transaction id it chose and confirming the
    // question section, so reaching this assertion is already most of the evidence.
    let a = kdig(port, &["kdig.example.com", "A"]).await?;
    assert!(
        a.contains("NOERROR"),
        "kdig read a non-zero rcode out of the A reply:\n{a}"
    );
    assert!(
        a.contains("93.184.216.44"),
        "kdig did not decode the address we answered with:\n{a}"
    );

    // --- TXT record --------------------------------------------------------
    //
    // A different rdata shape, and the one where an encoder most often gets the length octet of
    // the character-string wrong — a mistake a round-trip through our own codec cannot see.
    let txt = kdig(port, &["kdig.example.com", "TXT"]).await?;
    assert!(
        txt.contains("answered-by-netget"),
        "kdig did not decode the TXT character-string:\n{txt}"
    );

    // --- AAAA, MX and CNAME ------------------------------------------------
    //
    // Three rdata shapes the model can produce and no third-party resolver had ever read. Until
    // this pass the evidence covered A and TXT, and `metadata()` said so ("UNPROVEN: ... record
    // types beyond A and TXT") — which left `send_dns_aaaa_response`,
    // `send_dns_mx_response` and `send_dns_cname_response` as actions the model is offered and
    // nothing independent has ever decoded. A 16-byte address, a `u16` + a domain name, and a
    // bare domain name are each a different way to get an encoder wrong.
    let aaaa = kdig(port, &["kdig.example.com", "AAAA"]).await?;
    assert!(
        aaaa.contains("2001:db8::2c"),
        "kdig did not decode the AAAA rdata; a 16-octet address printed back in canonical form \
         is the assertion:\n{aaaa}"
    );

    // 4660 is 0x1234: byte-swapped it reads 13330, so a wrong-endian preference is visible
    // rather than plausible. Preference is the only integer rdata field in the whole action
    // set.
    let mx = kdig(port, &["kdig.example.com", "MX"]).await?;
    assert!(
        mx.contains("4660"),
        "kdig read a different MX preference than the 4660 we sent — 13330 means the u16 went \
         out byte-swapped:\n{mx}"
    );
    assert!(
        mx.contains("mail.kdig.example.com"),
        "kdig did not decode the MX exchange name:\n{mx}"
    );

    let cname = kdig(port, &["kdig.example.com", "CNAME"]).await?;
    assert!(
        cname.contains("www.kdig.example.com"),
        "kdig did not decode the CNAME target:\n{cname}"
    );

    // --- NXDOMAIN ----------------------------------------------------------
    //
    // The negative answer is a positive assertion of its own: a resolver caches it. kdig exits 0
    // for NXDOMAIN, so this asserts on what it printed rather than on the exit status.
    let missing = kdig(port, &["missing.kdig.example.com", "A"]).await?;
    assert!(
        missing.contains("NXDOMAIN"),
        "kdig did not read NXDOMAIN out of the reply:\n{missing}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    Ok(())
}

//! The DNS server, driven by `dig` — a DNS client NetGet shares no code with.
//!
//! ## Why this file exists
//!
//! `tests/server/dns/test.rs` drives the server with **hickory-client**, and the server
//! builds every response with **hickory-proto**. Those are the same project: hickory-client
//! depends on hickory-proto and decodes with the same codec that encoded the bytes. So the
//! existing suite proves the wire format is self-consistent, not that it is correct — the
//! same circularity that kept `rss` at Experimental until `feed-rs` did its parsing, and that
//! keeps `websocket` and `webrtc_signaling` there now. `tests/server/dns/CLAUDE.md` listed
//! "same library family as server-side hickory-proto" as an *advantage*.
//!
//! `dig` is ISC BIND's resolver. It shares no line of code with hickory, and it is the
//! program that decides whether a real operator believes a nameserver works. It is also
//! stricter than the round-trip: it checks that the transaction id it chose comes back, that
//! the question section matches the question it asked, and it reports the RCODE, so a
//! response any of those three would make a resolver discard fails here and passes there.
//!
//! ## No skip-when-missing
//!
//! If `dig` is absent this test **fails**, following `tests/server/npm/e2e_test.rs`. A test
//! that prints `SKIP` and returns `Ok(())` is a silent pass on any runner without the binary,
//! which is exactly how `kubernetes`, `oci_registry`, `maven` and `websocket` ended up with
//! maturity ratings resting on nothing. `dig` ships in the macOS base system and in the
//! `bind9-dnsutils` package present on the GitHub Ubuntu runner images.


use super::super::super::helpers::{self, E2EResult, NetGetConfig};
use tokio::process::Command;

/// Run `dig` against a NetGet DNS server on loopback and return its stdout.
///
/// `+tries=1` and `+time=5` keep exactly one query on the wire per call, so `expect_calls(1)`
/// in the mocks means what it says — dig retries by default, and each retry is another
/// `dns_query` event and another mock call.
///
/// `+noedns` for the same reason, and it is honest rather than convenient: this server does
/// not implement EDNS0 (`src/server/dns/CLAUDE.md` says so — the OPT record in a query is
/// ignored and none is added to responses). A dig that offers EDNS and gets a reply with no
/// OPT record may fall back and re-query, which would be a second `dns_query`. Newer dig
/// versions also send an EDNS COOKIE by default; `+nocookie` is *not* used to suppress it
/// because DiG 9.10, which ships with macOS, rejects that option outright — `+noedns` covers
/// it on every version.
/// **`tokio::process::Command`, never `std::process::Command`** — and this cost a debugging
/// pass, so it is worth stating why. `std::process::Command::output()` blocks the calling
/// thread until the child exits. Each `#[tokio::test]` runs on a current-thread runtime, and
/// the **mock Ollama server is in-process on that same runtime**. So a blocking `dig` parks
/// the very runtime that has to answer the `dns_query` event: dig's datagram arrived, NetGet
/// asked the model, the model could not reply because its executor was blocked waiting for
/// dig, and dig timed out after 5s having received nothing. The symptom was
/// `;; connection timed out; no servers could be reached` against a server that was up and
/// listening — indistinguishable from a broken server, and it is neither. The harness's own
/// stderr pump was blocked too, which is why the log showed five seconds of silence rather
/// than the query arriving.
async fn dig(port: u16, args: &[&str]) -> E2EResult<String> {
    let server = "@127.0.0.1";
    let port_arg = port.to_string();
    let mut argv: Vec<&str> = vec![server, "-p", &port_arg, "+tries=1", "+time=5", "+noedns"];
    argv.extend_from_slice(args);

    let out = Command::new("dig")
        .args(&argv)
        .output()
        .await
        .map_err(|e| {
            format!(
                "`dig` is not available ({e}): this test's whole point is driving a DNS client \
             that shares no code with the hickory stack the server encodes with, and \
             skipping it would leave the DNS server's maturity rating resting on a codec \
             round-tripping through itself"
            )
        })?;

    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        // Printed as well as returned. The harness's `Drop` panics on an un-verified mock
        // before a returned `Err` is rendered, so without this the only visible symptom is
        // "expected 1, got 0" — which says the server was never asked and not why.
        eprintln!(
            "dig {} exited {}\nstdout:\n{}\nstderr:\n{}",
            argv.join(" "),
            out.status,
            stdout,
            String::from_utf8_lossy(&out.stderr)
        );
        return Err(format!(
            "dig {} exited {}\nstdout:\n{}\nstderr:\n{}",
            argv.join(" "),
            out.status,
            stdout,
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(stdout)
}

/// One server, three queries, three mocked handlers — the whole file is 4 LLM calls.
///
/// Bundled into one server rather than one per case because each spawn is an extra startup
/// call and several seconds; the suite budget is ~10 calls.
#[tokio::test]
async fn test_dns_answers_dig() -> E2EResult<()> {
    println!("\n=== E2E Test: DNS answered by ISC dig ===");

    // Fail before spawning a server if the client this test exists for is missing.
    if let Err(e) = Command::new("dig").arg("-v").output().await {
        return Err(format!(
            "`dig` is not available ({e}): this test's whole point is driving a DNS client \
             that shares no code with the hickory stack the server encodes with, and \
             skipping it would leave the DNS server's maturity rating resting on a codec \
             round-tripping through itself"
        )
        .into());
    }

    let prompt = "listen on port {AVAILABLE_PORT} via dns. Resolve dig.example.com to \
                  93.184.216.34, answer TXT for dig.example.com, NXDOMAIN everything else";

    let server_config = NetGetConfig::new(prompt)
        .with_log_level("debug")
        .with_mock(|mock| {
            mock
                // Most specific first: `and_event_data_contains` is a substring match, and
                // "dig.example.com" is a substring of "missing.dig.example.com".
                .on_event("dns_query")
                .and_event_data_contains("domain", "missing.dig.example.com")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_dns_nxdomain",
                        "query_id": event["query_id"],
                        "domain": event["domain"],
                        "query_type": event["query_type"],
                    }])
                })
                .expect_calls(1)
                .and()
                .on_event("dns_query")
                .and_event_data_contains("domain", "dig.example.com")
                .and_event_data_contains("query_type", "TXT")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_dns_txt_response",
                        "query_id": event["query_id"],
                        "domain": event["domain"],
                        "text": "netget-dig-probe",
                        "ttl": 300,
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
                        "ip": "2001:db8::22",
                        "ttl": 300,
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
                        "exchange": "mail.dig.example.com.",
                        "preference": 4660,
                        "ttl": 300,
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
                        "target": "www.dig.example.com.",
                        "ttl": 300,
                    }])
                })
                .expect_calls(1)
                .and()
                .on_event("dns_query")
                .and_event_data_contains("domain", "dig.example.com")
                .and_event_data_contains("query_type", "A")
                .respond_with_actions_from_event(|event| {
                    serde_json::json!([{
                        "type": "send_dns_a_response",
                        "query_id": event["query_id"],
                        "domain": event["domain"],
                        "ip": "93.184.216.34",
                        "ttl": 300,
                    }])
                })
                // A floor, not an equality, and only for this rule: it is matched twice, once
                // by the `+noedns` A query and once by the default-dig query at the end, and
                // the second of those is allowed to re-query if dig decides to fall back from
                // EDNS. Two is the expected number; three would also be correct.
                .expect_at_least(2)
                .and()
                .on_instruction_containing("listen on port")
                .and_instruction_containing("dns")
                .respond_with_actions(serde_json::json!([
                    {
                        "type": "open_server",
                        "port": 0,
                        "base_stack": "DNS",
                        "instruction": "Resolve dig.example.com to 93.184.216.34, answer TXT, NXDOMAIN otherwise"
                    }
                ]))
                .expect_calls(1)
                .and()
        });

    let server = helpers::start_netget_server(server_config).await?;
    let port = server.port;

    // Wait for the server's own readiness line before the first query.
    //
    // Not decoration: `start_netget_server` returns when startup is *parsed*, and the UDP
    // socket may not be bound yet. A datagram to an unbound local port draws an ICMP port
    // unreachable, and dig treats that as a hard communications error and exits **at once** —
    // no retry, no 5-second timeout, just a failure that looks nothing like a slow server.
    // That is what this test did on its first run. The sibling tests in `test.rs` paper over
    // the same race with `sleep(500ms)`, which is the fixed-sleep anti-pattern; waiting on the
    // condition is both faster and correct under `--test-threads=100`.
    server
        .wait_for_log("DNS server listening on", 20)
        .await
        .map_err(|e| format!("DNS server never reported a listening socket: {e}"))?;
    println!("DNS server listening on port {port}");

    // --- A record ---------------------------------------------------------------------
    // `+short` prints only the rdata, and prints it only for a reply dig accepted: a
    // mismatched transaction id or question section yields no line at all.
    let a = dig(port, &["dig.example.com", "A", "+short"]).await?;
    assert_eq!(
        a.trim(),
        "93.184.216.34",
        "dig must accept the A answer and read the address out of it; got {a:?}"
    );
    println!("  ✓ A  -> {}", a.trim());

    // --- TXT record -------------------------------------------------------------------
    // dig prints TXT rdata quoted, per RFC 1035 presentation format.
    let txt = dig(port, &["dig.example.com", "TXT", "+short"]).await?;
    assert_eq!(
        txt.trim(),
        "\"netget-dig-probe\"",
        "dig must accept the TXT answer and print its character-string; got {txt:?}"
    );
    println!("  ✓ TXT -> {}", txt.trim());

    // --- AAAA, MX and CNAME -----------------------------------------------------------
    //
    // Three rdata shapes the model can produce and that no third-party resolver had ever read
    // before this pass — `metadata()` said so in as many words ("UNPROVEN: ... record types
    // beyond A and TXT"), which left three advertised actions with no independent decoding
    // behind them. A 16-octet address, a `u16` followed by a domain name, and a bare domain
    // name are each a different way to get an encoder wrong.
    let aaaa = dig(port, &["dig.example.com", "AAAA", "+short"]).await?;
    assert_eq!(
        aaaa.trim(),
        "2001:db8::22",
        "dig must decode the AAAA rdata and print it in canonical form; got {aaaa:?}"
    );
    println!("  ✓ AAAA -> {}", aaaa.trim());

    // 4660 is 0x1234, so a byte-swapped preference reads 13330 rather than something
    // plausible. It is the only integer rdata field in the whole DNS action set.
    let mx = dig(port, &["dig.example.com", "MX", "+short"]).await?;
    assert_eq!(
        mx.trim(),
        "4660 mail.dig.example.com.",
        "dig must decode the MX preference and exchange; 13330 would mean the u16 went out \
         byte-swapped. Got {mx:?}"
    );
    println!("  ✓ MX  -> {}", mx.trim());

    let cname = dig(port, &["dig.example.com", "CNAME", "+short"]).await?;
    assert_eq!(
        cname.trim(),
        "www.dig.example.com.",
        "dig must decode the CNAME target; got {cname:?}"
    );
    println!("  ✓ CNAME -> {}", cname.trim());

    // --- a DEFAULT dig, with EDNS on --------------------------------------------------
    //
    // Every query above passes `+noedns`, and the reason given for it is honest but narrow:
    // this server does not implement EDNS0, and a resolver that offers EDNS and gets a reply
    // with no OPT record *may* fall back and re-query, which would break `expect_calls(1)`.
    //
    // That left the question nobody had asked: does a resolver **as a user actually invokes
    // it** get an answer at all? Every modern resolver sends EDNS by default, so if the answer
    // were no, "works against real clients" would be a claim about a configuration nobody uses
    // — the `mysql_native_password` situation, where the rating rested on the one client
    // permissive enough to tolerate what is shipped.
    //
    // It is not. RFC 6891 §6.1.1 is explicit that a server which does not understand EDNS
    // answers without an OPT record, and the requestor then treats the response as coming from
    // a non-EDNS server. `expect_at_least` on the A rule above is what makes the fallback
    // harmless here: if dig does re-query, that is a second `dns_query` event and the count is
    // a floor rather than an equality.
    let default_dig = dig(port, &["dig.example.com", "A", "+short"]).await?;
    assert_eq!(
        default_dig.trim(),
        "93.184.216.34",
        "a dig invoked the way a person invokes it — EDNS on, no flags — must still resolve. \
         Got {default_dig:?}"
    );
    println!("  ✓ default dig (EDNS offered) -> {}", default_dig.trim());

    // --- NXDOMAIN ---------------------------------------------------------------------
    // Read from the header line rather than from an empty answer section: NOERROR with no
    // answers means "the name exists, it has no record of this type", which is a different
    // statement, and only the RCODE tells the two apart.
    let nx = dig(port, &["missing.dig.example.com", "A"]).await?;
    assert!(
        nx.contains("status: NXDOMAIN"),
        "dig must report RCODE 3 for send_dns_nxdomain; full reply:\n{nx}"
    );
    assert!(
        nx.contains("ANSWER: 0"),
        "an NXDOMAIN reply carries no answer records; full reply:\n{nx}"
    );
    // dig prints a `;; WARNING` line when the reply's id or question does not match what it
    // sent, and would have already refused the two `+short` queries above; assert the
    // absence explicitly so a regression in the echo cannot pass quietly here.
    assert!(
        !nx.contains(";; WARNING: ID mismatch"),
        "dig reported a transaction id mismatch; full reply:\n{nx}"
    );
    println!("  ✓ NXDOMAIN reported by dig, no answers, no id mismatch");

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("=== Test completed ===\n");
    Ok(())
}

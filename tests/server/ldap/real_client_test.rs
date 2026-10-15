//! `ldapsearch` (OpenLDAP) — the **second** independent client for the LDAP server.
//!
//! The rest of this directory drives `ldap3`. That is a genuine third-party implementation,
//! but it is **one** implementation, and a rating resting on one client is a rating resting on
//! that client's leniency. Elsewhere in this repository a second, stricter peer showed that no
//! conformant implementation could complete a call at all (`etcd` and `grpc` emitted no gRPC
//! trailers; `mysql` offered an auth plugin MySQL 9.0 had deleted), and in every one of those
//! cases the *error* path was accidentally correct and the tests asserted on the error path.
//!
//! This protocol's `e2e_testing` field used to claim "the ldapsearch/ldapadd command-line
//! tools" as evidence while **nothing asserting drove them** — `ldapsearch` appeared only in
//! `tests/eval/`, the real-model harness, which skips unless `NETGET_USE_OLLAMA=1` and reports
//! rather than asserts. This file is what that claim always should have been.
//!
//! # What `ldapsearch` adds over `ldap3`
//!
//! - **A different BER decoder in a different language.** OpenLDAP's `liblber` is C, written by
//!   the project that wrote the RFC. `ldap3` is Rust. They share no line of code, and this
//!   server hand-rolls its own BER encoder (`src/server/ldap/actions.rs`), so the encoder has
//!   exactly one thing checking it per client.
//! - **The long-form BER length.** `encode_ber_length` switches to the `0x81`/`0x82` long form
//!   past 127 bytes. Nothing in `e2e_test.rs` sends an entry big enough to reach it; the
//!   `description` attribute below is sized so that every `SearchResultEntry` here does.
//! - **The rendered result, not the deserialised one.** The assertions are on the LDIF a person
//!   would read: one `dn:` line per entry, one `attr: value` line per value of a multi-valued
//!   attribute, in the order the server sent the entries. A `SET OF` that dropped every value
//!   but the first is a missing line here and an indistinguishable `Vec<String>` there.
//! - **The resultCode as an exit status.** `ldapsearch` exits with the LDAP resultCode and
//!   names it, so `noSuchObject` (32) is read off the wire rather than inferred.
//!
//! # Non-vacuity: what was broken, and what the client then printed
//!
//! Verified by breaking the server and watching `ldapsearch`'s own output change — a test that
//! passes against a broken server is the failure mode this whole file exists to catch.
//!
//! `encode_search_entry` in `src/server/ldap/actions.rs` builds a `SET OF` per attribute.
//! Truncating it to the first value only —
//!
//! ```ignore
//! if let Some(arr) = attr_values.as_array() {
//!     for val in arr.iter().take(1) {          // ← the break
//! ```
//!
//! — left the wire well-formed, so nothing failed to parse. `ldapsearch` then printed
//!
//! ```text
//! objectClass: person
//! ```
//!
//! where it had printed
//!
//! ```text
//! objectClass: person
//! objectClass: inetOrgPerson
//! objectClass: top
//! ```
//!
//! and the test failed naming the missing values (`left: Some(["person"])`).
//!
//! The second break was `encode_ber_length` forced to the short form for every length (`if
//! true` in place of `if length < 128`), so the long-form branch never ran. The long entry's
//! length byte wrapped, and `ldapsearch` printed **no LDIF at all**, wrote
//!
//! ```text
//! ldap_result: Local error (-2)
//! ```
//!
//! to stderr and exited **254**. Both breaks were reverted; `git diff src/server/ldap/` is
//! empty.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features ldap \
//!       --test server -- server::ldap::real_client --test-threads=8


use crate::helpers::{self, E2EResult, NetGetConfig};
use std::collections::BTreeMap;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

/// Where an `ldapsearch` may be found, in the order an operator would reach for one.
///
/// PATH first — that is the binary a person types. The rest are the places OpenLDAP's tools
/// hide when the distribution keeps them out of PATH: Homebrew's keg-only `openldap`, and the
/// `libexec`/`lib` layouts some Linux packagings use.
const LDAPSEARCH_CANDIDATES: &[&str] = &[
    "ldapsearch",
    "/opt/homebrew/opt/openldap/bin/ldapsearch",
    "/usr/local/opt/openldap/bin/ldapsearch",
    "/usr/bin/ldapsearch",
    "/usr/lib/openldap/ldapsearch",
    "/usr/libexec/openldap/ldapsearch",
];

/// Fail — never skip — unless a usable `ldapsearch` exists, and say which one it is.
///
/// A `println!("SKIP: ldapsearch is not installed")` and `Ok(())` is a silent pass on every
/// runner without the binary, and a maturity rating resting on a test like that rests on
/// nothing wherever the suite actually runs. `tests/server/npm/e2e_test.rs` states the same
/// rule in its own words; `.github/workflows/ci.yml`'s `registry-audit` job installs the
/// OpenLDAP tools for this reason.
async fn require_ldapsearch() -> E2EResult<(String, String)> {
    let mut tried = Vec::new();
    for candidate in LDAPSEARCH_CANDIDATES {
        let out = timeout(
            Duration::from_secs(30),
            Command::new(candidate)
                .arg("-VV")
                .stdin(Stdio::null())
                .output(),
        )
        .await
        .map_err(|_| format!("`{candidate} -VV` did not finish within 30s"))?;

        match out {
            // `ldapsearch -VV` writes its banner to stderr and exits 0.
            Ok(out) if out.status.success() => {
                let banner = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                let version = banner
                    .lines()
                    .next()
                    .unwrap_or("ldapsearch (version unknown)")
                    .trim()
                    .to_string();
                return Ok(((*candidate).to_string(), version));
            }
            Ok(out) => tried.push(format!("{candidate}: exited {}", out.status)),
            Err(e) => tried.push(format!("{candidate}: {e}")),
        }
    }

    Err(format!(
        "no usable `ldapsearch` was found, so the LDAP server's SECOND independent client \
         cannot be driven and this test must fail rather than skip: skipping would leave the \
         protocol's Beta rating resting on `ldap3` alone, which is the single-client situation \
         this file exists to close. Install the OpenLDAP client tools with \
         `brew install openldap` (macOS) or `apt-get install -y ldap-utils` (Debian/Ubuntu). \
         Tried: {}",
        tried.join("; ")
    )
    .into())
}

/// One parsed LDIF entry: its DN and every attribute with every value, in wire order.
#[derive(Debug, Default)]
struct LdifEntry {
    dn: String,
    attrs: BTreeMap<String, Vec<String>>,
}

/// Parse `ldapsearch -LLL` output into entries.
///
/// A real parse rather than a substring match: the point of a second client is that it *parses
/// and prints*, so the assertions have to read structure back out of what it printed. Blank
/// lines separate entries; `name: value` is one value; a leading space continues the previous
/// line (LDIF folds at 78 columns, which every value here is deliberately short enough to
/// avoid, but a parser that ignored folding would silently truncate if that ever changed);
/// `name:: value` is base64, which nothing here should produce, so it is surfaced as a
/// distinctive marker rather than decoded.
fn parse_ldif(text: &str) -> Vec<LdifEntry> {
    let mut entries: Vec<LdifEntry> = Vec::new();
    let mut current: Option<LdifEntry> = None;
    // (attribute, is_dn) of the line a continuation would extend.
    let mut last_key: Option<String> = None;

    for raw in text.lines() {
        if raw.trim().is_empty() {
            if let Some(e) = current.take() {
                entries.push(e);
            }
            last_key = None;
            continue;
        }
        // LDIF comment (`-LLL` suppresses most, but not all builds suppress all of them).
        if raw.starts_with('#') {
            continue;
        }
        // A continuation of the previous value.
        if let Some(rest) = raw.strip_prefix(' ') {
            if let (Some(entry), Some(key)) = (current.as_mut(), last_key.as_ref()) {
                if key == "dn" {
                    entry.dn.push_str(rest);
                } else if let Some(values) = entry.attrs.get_mut(key) {
                    if let Some(last) = values.last_mut() {
                        last.push_str(rest);
                    }
                }
            }
            continue;
        }

        let Some((key, rest)) = raw.split_once(':') else {
            continue;
        };
        // `name:: value` is base64. Keep the marker in the key so an assertion on the plain
        // name fails loudly instead of quietly matching nothing.
        let (key, value) = match rest.strip_prefix(':') {
            Some(b64) => (format!("{key}::"), b64.trim_start().to_string()),
            None => (key.to_string(), rest.trim_start().to_string()),
        };

        if key == "dn" {
            if let Some(e) = current.take() {
                entries.push(e);
            }
            current = Some(LdifEntry {
                dn: value,
                attrs: BTreeMap::new(),
            });
        } else if let Some(entry) = current.as_mut() {
            entry.attrs.entry(key.clone()).or_default().push(value);
        }
        last_key = Some(key);
    }
    if let Some(e) = current.take() {
        entries.push(e);
    }
    entries
}

/// A `description` long enough that the entry's BER length needs the long form.
///
/// `encode_ber_length` emits a single byte below 128 and `0x81 <len>` from 128 to 255. Nothing
/// in `e2e_test.rs` reaches that branch, so this is the only place either length encoding is
/// checked by a client that is not ours.
const LONG_DESCRIPTION: &str = "Senior directory engineer, responsible for the replication \
     topology, the schema review board and the quarterly access recertification run";

/// Run `ldapsearch` against the NetGet server and return (stdout, stderr, exit code).
///
/// `tokio::process::Command`, not `std::process`: `#[tokio::test]` runs a current-thread
/// runtime, so a blocking `output()` parks the only worker — which is also the task draining
/// the netget child's stdout and stderr. The pipes fill, netget blocks inside a log call while
/// it is serving this very search, and `ldapsearch` times out against a server that is
/// behaving perfectly. The symptom looks exactly like a protocol bug.
async fn ldapsearch(bin: &str, port: u16, base_dn: &str) -> E2EResult<(String, String, i32)> {
    let url = format!("ldap://127.0.0.1:{port}");
    let out = timeout(
        Duration::from_secs(60),
        Command::new(bin)
            // -x simple auth (the default is SASL, which this server does not implement);
            // -LLL LDIF with no comments and no version header, so what is parsed below is
            // exactly the entries; -o nettimeout so a hung server fails rather than hangs.
            .args(["-x", "-LLL"])
            .args(["-o", "nettimeout=30"])
            .args(["-H", &url])
            .args(["-D", "cn=admin,dc=example,dc=com"])
            .args(["-w", "secret"])
            .args(["-b", base_dn])
            .arg("(objectClass=person)")
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| format!("ldapsearch against {url} base {base_dn} did not finish within 60s"))??;

    Ok((
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.code().unwrap_or(-1),
    ))
}

/// One netget server; two `ldapsearch` sessions against it.
///
/// LLM calls: 1 startup + 2 binds + 2 searches + up to 2 unbinds = **7**.
#[tokio::test]
async fn ldapsearch_completes_a_session_against_the_ldap_server() -> E2EResult<()> {
    let (bin, version) = require_ldapsearch().await?;
    println!("\n=== E2E: real ldapsearch client ===\n  {bin}\n  {version}");

    let prompt = "Start an LDAP directory server on port 0. Accept the admin bind, answer a \
         search under dc=example,dc=com with the two people entries, and answer a search under \
         any other base with noSuchObject.";

    let config = NetGetConfig::new_no_scripts(prompt).with_mock(|mock| {
        mock.on_instruction_containing("LDAP")
            .respond_with_actions(serde_json::json!([{
                "type": "open_server",
                "port": 0,
                "base_stack": "LDAP",
                "instruction": "Accept the admin bind; serve two people under dc=example,dc=com"
            }]))
            .expect_calls(1)
            .and()
            // The bind ldapsearch sends before every search. `message_id` is echoed from the
            // event: a client matches replies by messageID alone, so a hardcoded one is
            // answered to the wrong question or to none at all.
            .on_event("ldap_bind")
            .respond_with_actions_from_event(|event| {
                serde_json::json!([{
                    "type": "ldap_bind_response",
                    "message_id": event.get("message_id").and_then(|v| v.as_u64()).unwrap_or(1),
                    "success": true,
                    "message": "Bind successful"
                }])
            })
            .expect_calls(2)
            .and()
            // ONE rule that branches on the base DN. Two rules on `ldap_search` would be
            // first-match-wins: the first would answer both searches and the second would
            // report zero calls.
            .on_event("ldap_search")
            .respond_with_actions_from_event(|event| {
                let message_id = event
                    .get("message_id")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(2);
                let base_dn = event
                    .get("base_dn")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                if base_dn.ends_with("dc=example,dc=com") {
                    serde_json::json!([{
                        "type": "ldap_search_response",
                        "message_id": message_id,
                        "result_code": 0,
                        "entries": [
                            {
                                "dn": "cn=alice,ou=people,dc=example,dc=com",
                                "attributes": {
                                    "cn": ["alice"],
                                    "mail": ["alice@example.com", "a.hopper@example.com"],
                                    "objectClass": ["person", "inetOrgPerson", "top"],
                                    "description": [LONG_DESCRIPTION]
                                }
                            },
                            {
                                "dn": "cn=bob,ou=people,dc=example,dc=com",
                                "attributes": {
                                    "cn": ["bob"],
                                    "mail": ["bob@example.com"],
                                    "objectClass": ["person", "top"],
                                    "telephoneNumber": ["+1 555 0100"]
                                }
                            }
                        ]
                    }])
                } else {
                    // 32 = noSuchObject.
                    serde_json::json!([{
                        "type": "ldap_search_response",
                        "message_id": message_id,
                        "result_code": 32,
                        "entries": []
                    }])
                }
            })
            .expect_calls(2)
            .and()
            // RFC 4511 forbids a response to an unbind and the event declares no actions, so
            // nothing reads this — but the server raises it on a tracked task, and an
            // unmatched request would be answered HTTP 500 by the mock for no reason. It is
            // `expect_at_most` because the task races the test's own teardown.
            .on_event("ldap_unbind")
            .respond_with_actions(serde_json::json!([]))
            .expect_at_most(2)
            .and()
    });

    let server = timeout(
        Duration::from_secs(90),
        helpers::start_netget_server(config),
    )
    .await
    .map_err(|_| "netget startup timed out")??;
    helpers::wait_for_server_listening(&server, Duration::from_secs(30)).await?;
    let port = server.port;
    println!("  LDAP server on port {port}");

    // ---- Session 1: bind, search, and the entries ldapsearch rendered ----
    let (stdout, stderr, code) = ldapsearch(&bin, port, "dc=example,dc=com").await?;
    println!("  ldapsearch stdout:\n{stdout}\n  ldapsearch stderr:\n{stderr}\n  exit={code}");

    assert_eq!(
        code, 0,
        "ldapsearch exited {code} — it could not complete the bind+search session.\n\
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // The bind's `diagnosticMessage`, rendered by the client. `ldapsearch` prints the bind
    // result it received before it prints any entry, so this is the model's own string coming
    // back off the wire rather than a code the server could have substituted.
    assert!(
        stderr.contains("ldap_bind: Success (0)") && stderr.contains("Bind successful"),
        "ldapsearch did not render the bind result and diagnostic the model chose.\n\
         stderr:\n{stderr}"
    );

    let entries = parse_ldif(&stdout);
    assert_eq!(
        entries.len(),
        2,
        "ldapsearch rendered {} entries, expected 2.\nstdout:\n{stdout}",
        entries.len()
    );

    // Entry order is the order the SearchResultEntry messages were written.
    assert_eq!(entries[0].dn, "cn=alice,ou=people,dc=example,dc=com");
    assert_eq!(entries[1].dn, "cn=bob,ou=people,dc=example,dc=com");

    // Multi-valued attributes: every value of the `SET OF`, not just the first. This is the
    // assertion the truncation break in the module docs failed.
    assert_eq!(
        entries[0].attrs.get("objectClass").map(Vec::as_slice),
        Some(
            ["person", "inetOrgPerson", "top"]
                .map(String::from)
                .as_slice()
        ),
        "ldapsearch did not render all three objectClass values for alice.\n\
         It rendered: {:?}\nstdout:\n{stdout}",
        entries[0].attrs.get("objectClass")
    );
    assert_eq!(
        entries[0].attrs.get("mail").map(Vec::as_slice),
        Some(
            ["alice@example.com", "a.hopper@example.com"]
                .map(String::from)
                .as_slice()
        ),
        "ldapsearch did not render both mail values for alice.\nstdout:\n{stdout}"
    );
    assert_eq!(
        entries[0].attrs.get("cn").map(Vec::as_slice),
        Some(["alice"].map(String::from).as_slice())
    );

    // The long value: this entry's BER length is past 127, so `ldapsearch` decoded the
    // long-form length correctly in order to print it at all.
    assert_eq!(
        entries[0].attrs.get("description").map(Vec::as_slice),
        Some([LONG_DESCRIPTION].map(String::from).as_slice()),
        "ldapsearch did not render the long `description` verbatim — the long-form BER length \
         is the only thing between the encoder and this value.\nstdout:\n{stdout}"
    );

    assert_eq!(
        entries[1].attrs.get("telephoneNumber").map(Vec::as_slice),
        Some(["+1 555 0100"].map(String::from).as_slice()),
        "ldapsearch did not render bob's telephoneNumber.\nstdout:\n{stdout}"
    );
    assert_eq!(
        entries[1].attrs.get("objectClass").map(Vec::as_slice),
        Some(["person", "top"].map(String::from).as_slice())
    );

    // Nothing was base64-folded: every value above is an LDIF safe string, so a `name::` key
    // here would mean the server put something on the wire that is not what the model wrote.
    for entry in &entries {
        for key in entry.attrs.keys() {
            assert!(
                !key.ends_with("::"),
                "ldapsearch base64-encoded `{key}` on {}, which means the value it received \
                 was not the ASCII the model supplied.\nstdout:\n{stdout}",
                entry.dn
            );
        }
    }

    // ---- Session 2: the resultCode, read off ldapsearch's own exit status ----
    let (err_stdout, err_stderr, err_code) = ldapsearch(&bin, port, "dc=nowhere,dc=test").await?;
    println!("  ldapsearch(noSuchObject) stdout:\n{err_stdout}\n  stderr:\n{err_stderr}\n  exit={err_code}");

    // ldapsearch exits with the LDAP resultCode it received.
    assert_eq!(
        err_code, 32,
        "ldapsearch exited {err_code}, not 32 (noSuchObject) — the resultCode the model chose \
         did not reach the client.\nstdout:\n{err_stdout}\nstderr:\n{err_stderr}"
    );
    assert!(
        err_stderr.contains("No such object"),
        "ldapsearch did not name the resultCode it received.\nstderr:\n{err_stderr}"
    );
    assert!(
        parse_ldif(&err_stdout).is_empty(),
        "ldapsearch rendered entries for a search the server refused.\nstdout:\n{err_stdout}"
    );

    server.wait_for_mocks(30).await;
    server.verify_mocks().await?;
    server.stop().await?;
    println!("  [TEST] ✓ ldapsearch completed a real session\n");
    Ok(())
}

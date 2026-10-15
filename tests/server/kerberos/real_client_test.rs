//! NetGet's KDC against two independent Kerberos implementations, run as subprocesses:
//!
//! - **MIT krb5** — `kinit` (UDP), `klist`, `kvno`, and `ktutil` to derive the service's
//!   keytab from its password;
//! - **Heimdal** — `kinit` (TCP), `klist`, `kgetcred`.
//!
//! Each pre-authenticates with the password (its own PBKDF2 and its own AES-CTS), decrypts the
//! AS-REP and the TGS-REP NetGet built, and shows the lifetime and flags the policy (a python
//! script standing in for the model) chose. MIT's `kvno -k` then decrypts the service ticket
//! with a key `ktutil` derived from the service's password — a key NetGet never handled — so a
//! green run means the ticket is real. Wrong passwords, unknown and revoked principals and an
//! unknown service are refused with the right errors; with the model unreachable, both get an
//! error and neither gets a ticket. All traffic passes through recording relays and is
//! dissected by tshark's `kerberos` dissector in both directions.
//!
//! The tests FAIL, not skip, when either implementation or tshark is missing — see
//! `support::INSTALL`. No LLM calls.

use super::support::{
    self, krb5_conf, run, tools, Via, ALICE_PASSWORD, REALM, SERVICE, SERVICE_PASSWORD,
};
use crate::helpers::pcap_oracle::{require_tshark, PcapOracle};
use chrono::NaiveDateTime;
use regex::Regex;
use std::path::Path;

fn tgt_name() -> String {
    format!("krbtgt/{REALM}@{REALM}")
}

/// tshark's kerberos dissector tries to decrypt a TGS-REP with keys it learnt earlier in the
/// capture and, holding none (no keytab is configured), reports the key it lacks at Warn
/// severity. That is a statement about the capture, not about the bytes: every structural
/// check stays enforced.
const NO_KEYTAB_NOTES: [&str; 2] = ["Missing keytype", "Used keymap="];

/// MIT `klist` prints `valid-starting expires service`; return the two times of `service`'s
/// line and the flags printed under it.
fn mit_klist_entry(text: &str, service: &str) -> (i64, i64, String) {
    let re = Regex::new(&format!(
        r"(\d\d/\d\d/\d{{2,4}} \d\d:\d\d:\d\d)\s+(\d\d/\d\d/\d{{2,4}} \d\d:\d\d:\d\d)\s+{}\s*\n((?:\t[^\n]*\n?)*)",
        regex::escape(service)
    ))
    .unwrap();
    let c = re
        .captures(text)
        .unwrap_or_else(|| panic!("klist shows no {service}:\n{text}"));
    let flags = Regex::new(r"Flags: (\w+)")
        .unwrap()
        .captures(&c[3])
        .map(|f| f[1].to_string())
        .unwrap_or_default();
    // MIT 1.20/1.22 `printtime` tries `%c`, `%d %b %Y %T`, then `%x %X` in a 20-byte buffer
    // (src/lib/krb5/krb/str_conv.c); in the C locale only the third fits: `10/15/26 04:43:52`.
    // A four-digit year is what an en_US locale gives, kept for anyone running without LC_ALL.
    let parse = |s: &str| {
        let date = s.split(' ').next().unwrap_or_default();
        let format = if date.len() == 8 {
            "%m/%d/%y %H:%M:%S"
        } else {
            "%m/%d/%Y %H:%M:%S"
        };
        NaiveDateTime::parse_from_str(s, format)
            .unwrap_or_else(|e| panic!("klist time {s:?}: {e}"))
            .and_utc()
            .timestamp()
    };
    (parse(&c[1]), parse(&c[2]), flags)
}

/// Write a keytab for `principal` the way an administrator would: MIT `ktutil` derives the
/// aes256 key from the password itself.
async fn keytab(
    t: &support::Tools,
    dir: &Path,
    conf: &Path,
    principal: &str,
    password: &str,
) -> std::path::PathBuf {
    let path = dir.join("svc.keytab");
    let script = format!(
        "addent -password -p {principal}@{REALM} -k 1 -e aes256-cts-hmac-sha1-96\n{password}\nwkt {}\nquit\n",
        path.display()
    );
    let r = run(&t.mit_ktutil, &[], conf, &dir.join("unused-cc"), &script).await;
    assert!(path.is_file(), "ktutil wrote no keytab:\n{}", r.text);
    path
}

fn oracle_udp(recording: &support::Recording) {
    let packets = recording.lock().unwrap().clone();
    assert!(
        packets.iter().any(|(to, _)| !*to),
        "the relay saw no reply from the KDC"
    );
    let mut oracle = PcapOracle::udp("kerberos").port(88);
    for note in NO_KEYTAB_NOTES {
        oracle = oracle.allow_expert_containing(note);
    }
    for (to_server, bytes) in &packets {
        oracle = if *to_server {
            oracle.to_server(bytes)
        } else {
            oracle.from_server(bytes)
        };
    }
    oracle.assert_clean();
}

fn oracle_tcp(streams: &std::sync::Arc<std::sync::Mutex<Vec<support::Recording>>>) {
    let streams = streams.lock().unwrap().clone();
    assert!(!streams.is_empty(), "the relay saw no TCP connection");
    for rec in streams {
        let chunks = rec.lock().unwrap().clone();
        if !chunks.iter().any(|(to, _)| !*to) {
            continue;
        }
        let mut oracle = PcapOracle::tcp("kerberos").port(88);
        for note in NO_KEYTAB_NOTES {
            oracle = oracle.allow_expert_containing(note);
        }
        for (to_server, bytes) in &chunks {
            oracle = if *to_server {
                oracle.to_server(bytes)
            } else {
                oracle.from_server(bytes)
            };
        }
        oracle.assert_clean();
    }
}

#[tokio::test]
async fn mit_kinit_and_kvno_against_netget_over_udp() {
    require_tshark();
    let t = tools();
    let kdc = support::start(support::policy(), support::params()).await;
    let (relay, recording) = support::udp_relay(kdc.addr()).await;
    let dir = tempfile::tempdir().unwrap();
    let conf = krb5_conf(dir.path(), relay, Via::Udp);
    let cc = dir.path().join("cc-alice");

    // A pre-authenticated TGT with the policy's lifetime and flags.
    let r = run(
        &t.mit_kinit,
        &["-f", "-r", "1d", "alice"],
        &conf,
        &cc,
        &format!("{ALICE_PASSWORD}\n"),
    )
    .await;
    assert!(
        r.ok,
        "MIT kinit failed:\n{}\n\nKDC log:\n{}",
        r.text,
        kdc.log_text()
    );
    let list = run(&t.mit_klist, &["-f", "-e"], &conf, &cc, "").await;
    assert!(list.ok, "klist: {}", list.text);
    let (start, end, flags) = mit_klist_entry(&list.text, &tgt_name());
    assert_eq!(
        end - start,
        7200,
        "the model's two-hour lifetime:\n{}",
        list.text
    );
    for f in ['F', 'R', 'I', 'A'] {
        assert!(flags.contains(f), "flag {f} (forwardable, renewable, initial, pre-authenticated) missing from {flags:?}:\n{}", list.text);
    }
    assert!(list.text.contains("renew until"), "{}", list.text);
    assert!(
        list.text.contains("aes256-cts-hmac-sha1-96"),
        "{}",
        list.text
    );

    // A service ticket, verified with a keytab MIT derived from the service's password.
    let kt = keytab(&t, dir.path(), &conf, SERVICE, SERVICE_PASSWORD).await;
    let kv = run(
        &t.mit_kvno,
        &["-k", kt.to_str().unwrap(), SERVICE],
        &conf,
        &cc,
        "",
    )
    .await;
    assert!(
        kv.ok && kv.text.contains("keytab entry valid"),
        "kvno -k:\n{}\n\nKDC log:\n{}",
        kv.text,
        kdc.log_text()
    );
    let list = run(&t.mit_klist, &["-f"], &conf, &cc, "").await;
    let (start, end, _) = mit_klist_entry(&list.text, &format!("{SERVICE}@{REALM}"));
    assert_eq!(
        end - start,
        3600,
        "the model's one-hour service ticket:\n{}",
        list.text
    );

    // An unknown service, per the policy.
    let kv = run(&t.mit_kvno, &["host/nope.netget.test"], &conf, &cc, "").await;
    assert!(!kv.ok, "a ticket for an unknown service:\n{}", kv.text);
    assert!(
        kv.text.contains("not found in Kerberos database"),
        "{}",
        kv.text
    );

    // A wrong password: refused by the KDC itself, never shown to the model.
    let bad = dir.path().join("cc-bad");
    let r = run(&t.mit_kinit, &["alice"], &conf, &bad, "not the password\n").await;
    assert!(!r.ok, "kinit with a wrong password succeeded:\n{}", r.text);
    assert!(
        r.text.contains("Password incorrect") || r.text.contains("Preauthentication failed"),
        "{}",
        r.text
    );
    assert!(
        kdc.wait_for_log("decision=preauth_failed").await,
        "{}",
        kdc.log_text()
    );

    // Unknown and revoked principals, per the policy.
    let r = run(
        &t.mit_kinit,
        &["eve"],
        &conf,
        &dir.path().join("cc-eve"),
        "x\n",
    )
    .await;
    assert!(
        !r.ok && r.text.contains("not found in Kerberos database"),
        "{}",
        r.text
    );
    let r = run(
        &t.mit_kinit,
        &["mallory"],
        &conf,
        &dir.path().join("cc-m"),
        "mallory-pw\n",
    )
    .await;
    assert!(
        !r.ok && r.text.to_lowercase().contains("revoked"),
        "{}",
        r.text
    );

    // What the model was shown: the verified pre-authentication, and never a password.
    let events = kdc.events("kerberos_as_request").await;
    assert!(
        events
            .iter()
            .any(|e| e["request"]["client"] == "alice" && e["request"]["preauth"] == "verified"),
        "{events:#?}"
    );
    let shown = serde_json::to_string(&kdc.state.list_access_logs_for(None, None).await).unwrap();
    for secret in [ALICE_PASSWORD, SERVICE_PASSWORD, "mallory-pw"] {
        assert!(!shown.contains(secret), "a password reached the access log");
        assert!(
            !kdc.log_text().contains(secret),
            "a password reached the log"
        );
    }

    oracle_udp(&recording);
}

#[tokio::test]
async fn heimdal_kinit_and_kgetcred_against_netget_over_tcp() {
    require_tshark();
    let t = tools();
    let kdc = support::start(support::policy(), support::params()).await;
    let (relay, streams) = support::tcp_relay(kdc.addr()).await;
    let dir = tempfile::tempdir().unwrap();
    let conf = krb5_conf(dir.path(), relay, Via::HeimdalTcp);
    let cc = dir.path().join("cc-alice");
    let pwfile = dir.path().join("pw");
    std::fs::write(&pwfile, ALICE_PASSWORD).unwrap();
    let pw_arg = format!("--password-file={}", pwfile.display());

    let r = run(
        &t.heimdal_kinit,
        &[
            &pw_arg,
            "--forwardable",
            "--renewable-life=1d",
            &format!("alice@{REALM}"),
        ],
        &conf,
        &cc,
        "",
    )
    .await;
    assert!(
        r.ok,
        "Heimdal kinit failed:\n{}\n\nKDC log:\n{}",
        r.text,
        kdc.log_text()
    );
    let list = run(
        &t.heimdal_klist,
        &t.heimdal_klist_args(&["-v"]),
        &conf,
        &cc,
        "",
    )
    .await;
    assert!(list.ok, "klist: {}", list.text);
    let block = list
        .text
        .split("Server: ")
        .find(|b| b.starts_with(&tgt_name()))
        .unwrap_or_else(|| panic!("no TGT in:\n{}", list.text));
    let time = |label: &str| {
        let re = Regex::new(&format!(
            r"{label}:\s+(\w{{3}}\s+\d+\s+\d\d:\d\d:\d\d\s+\d{{4}})"
        ))
        .unwrap();
        let s = re
            .captures(block)
            .unwrap_or_else(|| panic!("no {label} in:\n{block}"))[1]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        // Heimdal prints ctime(3) from the month on (kuser/klist.c printable_time_internal),
        // which is locale-independent and space-pads the day.
        NaiveDateTime::parse_from_str(&s, "%b %d %H:%M:%S %Y")
            .unwrap()
            .and_utc()
            .timestamp()
    };
    assert_eq!(time("End time") - time("Auth time"), 7200, "{block}");
    for f in ["forwardable", "renewable", "initial", "pre-authent"] {
        assert!(block.contains(f), "{f} missing:\n{block}");
    }

    let r = run(
        &t.heimdal_kgetcred,
        &[&format!("{SERVICE}@{REALM}")],
        &conf,
        &cc,
        "",
    )
    .await;
    assert!(
        r.ok,
        "kgetcred failed:\n{}\n\nKDC log:\n{}",
        r.text,
        kdc.log_text()
    );
    let list = run(&t.heimdal_klist, &t.heimdal_klist_args(&[]), &conf, &cc, "").await;
    assert!(
        list.text.contains(&format!("{SERVICE}@{REALM}")),
        "{}",
        list.text
    );

    let bad_pw = dir.path().join("badpw");
    std::fs::write(&bad_pw, "nope").unwrap();
    let r = run(
        &t.heimdal_kinit,
        &[
            &format!("--password-file={}", bad_pw.display()),
            &format!("alice@{REALM}"),
        ],
        &conf,
        &dir.path().join("cc-bad"),
        "",
    )
    .await;
    assert!(
        !r.ok,
        "Heimdal kinit with a wrong password succeeded:\n{}",
        r.text
    );
    assert!(
        kdc.wait_for_log("decision=preauth_failed").await,
        "{}",
        kdc.log_text()
    );

    oracle_tcp(&streams);
}

#[tokio::test]
async fn with_the_model_unreachable_both_clients_get_an_error_and_no_ticket() {
    let t = tools();
    // No routing rule: every event goes to a model at 127.0.0.1:1, which is not there.
    let kdc = support::start(None, support::params()).await;
    let dir = tempfile::tempdir().unwrap();

    let conf = krb5_conf(dir.path(), kdc.addr(), Via::MitTcp);
    let cc = dir.path().join("cc-mit");
    let r = run(
        &t.mit_kinit,
        &[support::LEGACY],
        &conf,
        &cc,
        &format!("{}\n", support::LEGACY_PASSWORD),
    )
    .await;
    assert!(!r.ok, "MIT kinit got a ticket with no model:\n{}", r.text);
    assert!(!cc.exists() || !run(&t.mit_klist, &[], &conf, &cc, "").await.ok);

    let conf = krb5_conf(dir.path(), kdc.addr(), Via::HeimdalTcp);
    let pw = dir.path().join("pw");
    std::fs::write(&pw, support::LEGACY_PASSWORD).unwrap();
    let cc = dir.path().join("cc-heimdal");
    let r = run(
        &t.heimdal_kinit,
        &[
            &format!("--password-file={}", pw.display()),
            &format!("{}@{REALM}", support::LEGACY),
        ],
        &conf,
        &cc,
        "",
    )
    .await;
    assert!(
        !r.ok,
        "Heimdal kinit got a ticket with no model:\n{}",
        r.text
    );
    assert!(
        kdc.wait_for_log("decision=fail_closed_llm_error").await,
        "{}",
        kdc.log_text()
    );
    assert!(
        !kdc.log_text().contains("decision=model_issue"),
        "{}",
        kdc.log_text()
    );
}

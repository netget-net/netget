//! Three shrink-only ratchets over the test suite itself.
//!
//! The suite is the evidence for every maturity rating in this repository. Where the suite
//! lies, the ratings lie — so the properties that decide whether a test asserts anything are
//! worth a build failure rather than a review comment.
//!
//! Each check reads the source tree, so it holds at the six-protocol CI gate as well as at
//! `--all-features`: a registry-walking test only ever sees what that build compiled, and 110
//! of the 116 protocols are not in the blocking job.
//!
//! **Every baseline below may only shrink.** Fix the test, then delete its line here.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tcp --test test_suite_hygiene_test

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `.rs` under `tests/`, as repo-relative slash-separated paths.
fn test_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    let root = repo_root();
    let mut paths = Vec::new();
    walk(&root.join("tests"), &mut paths);
    paths.sort();
    paths
        .into_iter()
        .map(|p| {
            let rel = p
                .strip_prefix(&root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            (rel, text)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 1. A reason on every `#[ignore]`
// ---------------------------------------------------------------------------

/// A bare `#[ignore]` is a test that has been switched off for a reason nobody wrote down.
///
/// That matters more here than in most repositories, because an ignore in this tree is load
/// bearing: it is what stands between a protocol's maturity rating and the evidence that
/// rating claims. `CLAUDE.md` records the MQTT case — four pub/sub tests sat behind stale
/// "MQTT broker not yet implemented" markers inside a `/* … */` block, so nothing even
/// compiled them, and a working broker was held at Experimental for months. A reason string
/// is the cheapest thing that makes that visible: `cargo test` prints it next to the test
/// name, so a stale one is read rather than inherited.
///
/// The reason must say what is missing (a binary, an adapter, root, a real model) rather than
/// that the test is "flaky" or "broken" — those are defects to investigate, not reasons.
///
/// **Baseline: zero, and it may only stay that way.** 105 bare attributes were converted in
/// September 2026; 97 had the reason sitting in a trailing `//` comment where no test runner
/// would ever show it, and 8 had nothing at all.
#[test]
fn every_ignore_attribute_carries_a_reason() {
    let mut bare: Vec<String> = Vec::new();
    for (path, text) in test_sources() {
        for (i, line) in text.lines().enumerate() {
            let t = line.trim_start();
            // `#[ignore]` exactly — `#[ignore = "…"]` is the form we want. A doc comment or
            // prose mentioning the attribute does not start the line, which is why this is
            // anchored: an unanchored search reports every paragraph that discusses it.
            if t.starts_with("#[ignore]") {
                bare.push(format!("{}:{}", path, i + 1));
            }
        }
    }
    assert!(
        bare.is_empty(),
        "{} test(s) are ignored with no reason. Write one into the attribute — \
         `#[ignore = \"needs a PC/SC reader with a card presented\"]` — or, if the reason has \
         gone stale, un-ignore the test and run it:\n  {}",
        bare.len(),
        bare.join("\n  ")
    );
}

// ---------------------------------------------------------------------------
// 2. No fixed second-scale sleeps in a protocol suite
// ---------------------------------------------------------------------------

/// Files that may still contain `sleep(Duration::from_secs(N))`, with how many.
///
/// A fixed sleep is a guess about how long something will take, and this repository has
/// measured what that guess is worth: `m3ua`'s suite went from 6s to 0.46s when three of them
/// became waits, and every "load-flaky" test investigated in `CLAUDE.md` — the doh keychain
/// stall, the port-0 probe race — was first noticed because a constant that was generous
/// alone was not generous at `--test-threads=100`.
///
/// The helpers that replace one are `wait_for_mocks`, `wait_for_any`, `wait_for_log`,
/// `wait_for_pattern`, `wait_for_regex` and `wait_for_server_listening`.
///
/// **Two kinds of entry below are legitimate and are expected to stay:**
///
/// * **The sleep is the thing under test.** `client/stomp` sleeps 30s to prove a silent broker
///   times out rather than hanging; `server/turn` sleeps past an allocation's lifetime;
///   `client/bgp`'s hold-timer and update tests sleep to prove that nothing happens. You
///   cannot wait on the absence of an event.
/// * **The sleep is a settle *after* a condition.** Waiting on a counter that is bumped before
///   the decision it guards leaves a real window; `tuntap`'s `wait_for_received` documents
///   exactly this. Keep those and say so in a comment.
///
/// Everything else on this list is a guess that has not been converted yet — most of it in
/// tests that are `#[ignore]`d for an external dependency and so never run. **The counts may
/// only shrink**, and a file that reaches zero comes off the list entirely.
const SLEEP_BASELINE: &[(&str, usize)] = &[
    ("tests/client/bgp/hold_timer_test.rs", 1),
    ("tests/client/bgp/update_reply_test.rs", 1),
    ("tests/client/bluetooth/command_channel_test.rs", 1),
    ("tests/client/dhcp/e2e_test.rs", 3),
    ("tests/client/git/e2e_test.rs", 2),
    ("tests/client/http_proxy/e2e_test.rs", 2),
    ("tests/client/isis/e2e_test.rs", 5),
    ("tests/client/maven/e2e_test.rs", 5),
    ("tests/client/nfs/e2e_test.rs", 4),
    ("tests/client/oauth2/e2e_test.rs", 5),
    ("tests/client/ollama/e2e_test.rs", 5),
    ("tests/client/ospf/e2e_test.rs", 2),
    ("tests/client/pop3/e2e_test.rs", 3),
    ("tests/client/pypi/e2e_test.rs", 4),
    ("tests/client/s3/e2e_test.rs", 4),
    ("tests/client/smb/e2e_test.rs", 4),
    ("tests/client/snmp/e2e_test.rs", 6),
    ("tests/client/socks5/e2e_test.rs", 1),
    ("tests/client/stomp/e2e_test.rs", 2),
    ("tests/client/tor/e2e_test.rs", 2),
    ("tests/client/wireguard/e2e_test.rs", 4),
    ("tests/client/x11/wire_test.rs", 1), // proves the depth-bounded chain stops: an absence
    ("tests/client/xmpp/e2e_test.rs", 3),
    ("tests/server/arp/e2e_test.rs", 1),
    ("tests/server/bluetooth_ble/e2e_test.rs", 2),
    // Leave a 4 MiB Connect response unread past its 1s RPC deadline to exercise backpressure cancellation.
    ("tests/server/connect_rpc/e2e_test.rs", 1),
    ("tests/server/dc/test.rs", 2),
    // Leave a 4 MiB Web response unread past its 1s RPC deadline: backpressure cancellation is under test.
    ("tests/server/grpc_web/e2e_test.rs", 1),
    ("tests/server/hls/curl_test.rs", 1),
    ("tests/server/doq/bounds_test.rs", 2), // a body held 1s inside the exchange bound; queries 2s apart inside the idle bound
    ("tests/server/dot/bounds_test.rs", 1), // queries 2s apart inside the idle bound, which each one resets
    ("tests/server/ftp/data_connection_test.rs", 2), // a data connection 1s into its connect bound; an upload paused 1s inside its idle bound
    ("tests/server/icmp/e2e_test.rs", 1),
    ("tests/server/igmp/e2e_test.rs", 1),
    ("tests/server/isis/e2e_test.rs", 3),
    ("tests/server/mqtt/connection_bounds_test.rs", 1), // PINGREQ once a second is the cadence under test
    ("tests/client/rtsp/real_server_test.rs", 1), // two seconds of media is the stream under test
    ("tests/server/openvpn/e2e_test.rs", 1),
    ("tests/server/rip/e2e_test.rs", 3),
    ("tests/server/rtp/e2e_test.rs", 1),
    ("tests/server/rtsp/ffprobe_test.rs", 1),
    ("tests/server/sip/e2e_test.rs", 1),
    ("tests/server/sip/rtp_interop_test.rs", 1),
    ("tests/server/syslog/e2e_test.rs", 1),
    ("tests/server/tor_integration/helpers.rs", 1),
    ("tests/server/torrent_integration/helpers.rs", 3),
    ("tests/server/turn/e2e_test.rs", 1),
];

#[test]
fn protocol_suites_do_not_wait_on_a_fixed_number_of_seconds() {
    let allowed: BTreeMap<&str, usize> = SLEEP_BASELINE.iter().copied().collect();
    let mut actual: BTreeMap<String, usize> = BTreeMap::new();

    for (path, text) in test_sources() {
        if !(path.starts_with("tests/server/") || path.starts_with("tests/client/")) {
            continue;
        }
        let n = text.matches("sleep(Duration::from_secs(").count();
        if n > 0 {
            actual.insert(path, n);
        }
    }

    let mut problems: Vec<String> = Vec::new();
    for (path, n) in &actual {
        match allowed.get(path.as_str()) {
            None => problems.push(format!(
                "{path}: {n} fixed second-scale sleep(s) in a file with none in the baseline. \
                 Wait on the condition — wait_for_mocks / wait_for_any / wait_for_log / \
                 wait_for_server_listening — or, if the sleep really is the thing under test, add it \
                 here with the reason."
            )),
            Some(&cap) if n > &cap => problems.push(format!(
                "{path}: {n} fixed second-scale sleep(s), baseline is {cap}. The baseline may \
                 only shrink."
            )),
            _ => {}
        }
    }
    // A stale baseline entry is a smaller problem, but it still misleads the next reader.
    for (path, cap) in &allowed {
        let n = actual.get(*path).copied().unwrap_or(0);
        if n < *cap {
            problems.push(format!(
                "{path}: baseline says {cap} fixed sleep(s) but the file has {n}. \
                 Lower the entry (or delete it if {n} is zero) — the ratchet has slipped."
            ));
        }
    }

    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

// ---------------------------------------------------------------------------
// 3. A configured mock is a verified mock
// ---------------------------------------------------------------------------

/// A test that configures `.with_mock(…)` and never calls `verify_mocks()` asserts nothing
/// about the model at all.
///
/// That is not a cosmetic gap. `expect_calls` is how these suites say "the server asked the
/// model once, about this event, and acted on the answer"; without the verification the rules
/// are inert decoration, the request falls through, and the test passes on whatever the
/// protocol happened to do. `CLAUDE.md` catalogues the failure this hides: whole suites mocked
/// against events their server never raises, fields the event does not carry, and actions the
/// protocol cannot execute — none of which fail loudly, because an unmatched rule simply never
/// matches.
///
/// The check is at file level deliberately. Most suites build their config in a helper and
/// verify in the test, so a per-function rule reports every one of those helpers; a file that
/// mocks somewhere and verifies nowhere cannot be that shape.
///
/// **Baseline: zero, and it may only stay that way.**
#[test]
fn a_file_that_configures_a_mock_also_verifies_it() {
    let mut unverified: Vec<String> = Vec::new();
    for (path, text) in test_sources() {
        if path.starts_with("tests/helpers/") {
            continue;
        }
        // Only count a real call. The two client suites that merely *name* `.with_mock()` in
        // an `#[ignore]` reason are talking about its absence, which is the opposite case.
        let configures = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .any(|l| l.contains(".with_mock(") && !l.contains("#[ignore"));
        if configures && !text.contains("verify_mocks") {
            unverified.push(path);
        }
    }
    assert!(
        unverified.is_empty(),
        "{} test file(s) configure a mock LLM and never verify it, so nothing in them asserts \
         anything about the model. Call `verify_mocks()` (after `wait_for_mocks(30)`):\n  {}",
        unverified.len(),
        unverified.join("\n  ")
    );
}

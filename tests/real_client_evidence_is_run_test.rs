//! Every real-client test must be run by a CI job that has its client installed.
//!
//! # Why this exists
//!
//! `.github/workflows/ci.yml` has a step whose own header says: *"These are the tests every Beta
//! rating that names a binary rests on, and this is the only job with those binaries, so it is
//! the only place they can run."* It drives them by name, in a hand-maintained list.
//!
//! A hand-maintained list of tests is a list that goes stale, and it did. On 22 September 2026,
//! diffing `tests/server/*/real_client_test.rs` against that list found **three** absent, and one
//! of them — `ollama` — was a **Beta** rating whose real-client test the job that exists to run
//! real-client tests did not run. That is precisely the hole the job closes for everyone else.
//!
//! # The second hole, found the same week
//!
//! The first version of this file looked for `real_client_test.rs` **by filename**, and that is
//! not what a real-client test is. `tests/server/dns/kdig_test.rs` drives Knot's `kdig`;
//! `tests/server/dns/dig_test.rs` drives ISC's `dig`; `tests/server/whois/e2e_test.rs` drives
//! `whois(1)`. All are real-client evidence and none matches the filename.
//!
//! So the scan is by **content**: a test file that spawns a binary NetGet does not ship is
//! driving a third-party client, whatever it is called.
//!
//! # The third hole, which is what actually broke the build
//!
//! The blocking `Test` job runs the `CI_PROTOCOL_TESTS` suites of the `server` and `client`
//! test binaries, so it **runs** every real-client test belonging to those protocols — whether or not the job
//! installs the client. On 22 September 2026 it ran `server::dns::kdig_test` and
//! `server::redis::real_client_test` with neither `kdig` nor `redis-cli` present, and those
//! tests hard-fail rather than skip (correctly: a `SKIP` that returns success is a silent pass).
//! Five of 71 tests failed and the blocking job was red.
//!
//! Filtering them out of that job was the wrong fix — the whole point of a hard-fail gate is
//! that nobody can quietly run a suite without the client, and a `--skip` list is one more
//! hand-maintained list to go stale. The job installs the binaries instead, and
//! [`ci_feature_clients_are_installed`] derives the required list from the test sources so it
//! cannot drift again.
//!
//! # The client side
//!
//! The same holds in the other direction. A NetGet *client* proves itself against a real
//! third-party *server* (`tests/client/<p>/real_server_test.rs`, driving `mosquitto`,
//! `redis-server`, `etcd`, `nginx` through `tests/helpers/real_server.rs`), and
//! `tests/client/nats/e2e_test.rs` spawns `nats-server` by hand. Until the scan covered
//! `tests/client/` too, the one Beta client's evidence ran in no CI job at all. Client entries
//! are keyed `client/<p>::<stem>`, and the loop runs them from the `client` test target.
//!
//! # Why this is a test and not a CI step
//!
//! It reads source and YAML and needs no build, no features and no binaries, so it holds at the
//! six-protocol CI gate as well as at `--all-features` — the same reason the other whole-tree
//! ratchets read source rather than walking the registry.
//!
//! # What it does not check
//!
//! That the filters *match* anything. A filter naming a test that was renamed would pass here and
//! silently run nothing in CI, because `cargo test <filter>` with no matches exits 0. That is a
//! real second hole and this test does not close it; closing it means CI asserting a non-zero
//! test count per filter, which belongs in the workflow rather than here.
//!
//! Nor does it check binaries reached from `tests/helpers/`, which is shared by every protocol
//! and so cannot be attributed to one. There is one today — `tshark`, from `pcap_oracle.rs` —
//! and the `Test` job installs it in a step of its own.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn workflow() -> String {
    let path = repo_root().join(".github").join("workflows").join("ci.yml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Binaries a test may spawn without that making it a real-client test.
///
/// `curl` and `python3` are on every GitHub runner image and every developer machine, and
/// `sh`/`ps` are the process-cleanup helper. `tshark` belongs to the pcap oracle, which the
/// `Test` job installs in its own step for its own reason. `protoc` is a **code generator**,
/// not a peer: `grpc`'s tests run it to build a descriptor set and it never speaks to a NetGet
/// server, so its presence says nothing about whether a third-party client completed a session.
///
/// Keep this list short and keep each entry justified. Every name added here is a real-client
/// test this scan stops seeing, which is the failure mode the scan exists to prevent.
const UBIQUITOUS: &[&str] = &[
    "/bin/sh", "sh", "ps", "curl", "python3", "python", "tshark", "protoc",
];

/// Test files that drive a third-party binary, keyed the way the CI loop names them:
///
/// * `tests/server/<p>/<stem>.rs` as `"<p>::<stem>"` — a real **client** against NetGet's
///   server, run from the `server` test target;
/// * `tests/client/<p>/<stem>.rs` as `"client/<p>::<stem>"` — a real **server** against
///   NetGet's client, run from the `client` test target. The client bar in `CLAUDE.md` is the
///   mirror of the server one, and its evidence has the same problem the server side had: a
///   hard-failing test nothing in CI runs proves nothing.
///
/// A file named `real_client_test.rs` (server side) or `real_server_test.rs` (client side)
/// counts even if this scan finds no spawned binary in it: some drive their peer through a
/// crate rather than a subprocess, and the name is then the only declaration there is.
fn real_client_tests() -> BTreeMap<String, BTreeSet<String>> {
    let mut out = scan_side("server", "", "real_client_test");
    out.extend(scan_side("client", "client/", "real_server_test"));
    out
}

fn scan_side(side: &str, key_prefix: &str, named_stem: &str) -> BTreeMap<String, BTreeSet<String>> {
    let dir = repo_root().join("tests").join(side);
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let entries =
        std::fs::read_dir(&dir).unwrap_or_else(|_| panic!("cannot read {}", dir.display()));
    for proto_dir in entries.flatten() {
        let proto_path = proto_dir.path();
        if !proto_path.is_dir() {
            continue;
        }
        let protocol = proto_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let files = match std::fs::read_dir(&proto_path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        for file in files.flatten() {
            let path = file.path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let stem = path.file_stem().unwrap().to_string_lossy().to_string();
            if stem == "mod" {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap_or_default();
            let bins = spawned_binaries(&src);
            if bins.is_empty() && stem != named_stem {
                continue;
            }
            out.insert(format!("{key_prefix}{protocol}::{stem}"), bins);
        }
    }
    out
}

/// Every `Command::new("…")` and `RealServer::builder("…")` argument in a source file, minus
/// [`UBIQUITOUS`].
///
/// A literal is the only form worth matching: a binary name held in a variable is not something
/// a source-reading scan can resolve, and every real-client gate in this tree writes the literal
/// because the error message has to name it anyway. `RealServer::builder` is
/// `tests/helpers/real_server.rs`, which spawns the server itself — so for the client suites the
/// builder's first argument is the only place the server binary is named at all.
fn spawned_binaries(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for needle in ["Command::new(\"", "RealServer::builder(\""] {
        let mut rest = src;
        while let Some(i) = rest.find(needle) {
            rest = &rest[i + needle.len()..];
            if let Some(end) = rest.find('"') {
                let name = &rest[..end];
                if !UBIQUITOUS.contains(&name) {
                    out.insert(name.to_string());
                }
                rest = &rest[end..];
            }
        }
    }
    out
}

/// Literal evidence filter lists across CI workflows. Dedicated protocol jobs
/// provision their peers separately from the broad registry job.
fn evidence_loop() -> String {
    let directory = repo_root().join(".github/workflows");
    let mut paths: Vec<_> = std::fs::read_dir(&directory)
        .expect("read workflow directory")
        .map(|entry| entry.expect("workflow entry").path())
        .filter(|path| {
            matches!(
                path.extension().and_then(|s| s.to_str()),
                Some("yml" | "yaml")
            )
        })
        .collect();
    paths.sort();
    let mut filters = String::new();
    for path in paths {
        let text = std::fs::read_to_string(&path).expect("read workflow");
        let mut in_list = false;
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            if line == "for filter in \\" {
                assert!(!in_list, "nested evidence list in {}", path.display());
                in_list = true;
            } else if in_list {
                if let Some(end) = line.find("; do") {
                    filters.push_str(&line[..end]);
                    filters.push(' ');
                    in_list = false;
                } else {
                    filters.push_str(line.trim_end_matches('\\').trim());
                    filters.push(' ');
                }
            }
        }
        assert!(!in_list, "unterminated evidence list in {}", path.display());
    }
    assert!(!filters.is_empty(), "no literal CI evidence filters found");
    filters
}

/// Real-client tests that no CI job runs today.
///
/// **This list may only shrink.** Each entry is a test that drives a genuine third-party client
/// and that no CI workflow executes, so whatever it proves is proved
/// nowhere. They are recorded rather than fixed here because each needs its own decision, and
/// the note says what that decision costs:
///
/// * `git::e2e_test` — drives the real `git` binary, which is **preinstalled on every runner**.
///   This is the cheapest of the four: adding `git::e2e_test` to the evidence loop needs no
///   package at all. `git`'s Beta rating rests on it.
/// * `whois::e2e_test` — drives `whois(1)` (package `whois`) and also uses the pcap oracle, so
///   the `registry-audit` job would need `tshark` as well, which it does not install today.
///   `whois`'s Beta rating rests on it.
/// * `tor_integration::tor_client` and `wireguard::e2e_test` — both `#[ignore]`d, so CI could
///   name them and still run nothing. CLAUDE.md treats unreachable evidence as disqualifying
///   for a rating rather than as something the loop must carry; `wireguard` is Experimental for
///   exactly that reason, and `tor_relay` is named in the same passage.
const NOT_RUN_ANYWHERE: &[&str] = &[
    "tor_integration::tor_client",
    "whois::e2e_test",
    "wireguard::e2e_test",
];

#[test]
fn the_scan_finds_real_client_tests() {
    // Without this, an empty scan would make the real assertions below vacuously true — the
    // shape that made `audit_event_action_declarations` exempt the worst case.
    let found = real_client_tests();
    assert!(
        found.len() >= 30,
        "found only {} real-client tests, which means the scan is broken rather than \
         that the tree lost them: {:?}",
        found.len(),
        found.keys().collect::<Vec<_>>()
    );
    assert!(
        found.contains_key("dns::kdig_test"),
        "the scan missed dns::kdig_test, which drives Knot's kdig — the exact naming shape \
         (a real-client test not called real_client_test.rs) this scan was rewritten to cover"
    );
}

#[test]
fn every_real_client_test_is_named_in_the_ci_evidence_loop() {
    let loop_text = evidence_loop();
    let baseline: BTreeSet<&str> = NOT_RUN_ANYWHERE.iter().copied().collect();

    let mut missing = Vec::new();
    let mut baseline_now_run = Vec::new();
    for (name, bins) in real_client_tests() {
        let protocol = name.split("::").next().unwrap();
        // `openvpn::` is a deliberate whole-protocol filter in the loop, so accept either the
        // exact module path or a filter that subsumes it.
        let named = loop_text.contains(&name) || loop_text.contains(&format!("{protocol}:: "));
        match (named, baseline.contains(name.as_str())) {
            (false, false) => missing.push(format!("{name}  (drives {bins:?})")),
            (true, true) => baseline_now_run.push(name),
            _ => {}
        }
    }

    assert!(
        baseline_now_run.is_empty(),
        "these are in NOT_RUN_ANYWHERE but CI now runs them — delete them from that list, it \
         may only shrink:\n\n  {}",
        baseline_now_run.join("\n  ")
    );

    assert!(
        missing.is_empty(),
        "these tests drive a third-party client and no CI workflow runs \
         them:\n\n  {}\n\n\
         Add the test to a workflow that provisions its pinned third-party peer. A real-client test outside such a job is \
         evidence nothing exercises — the same hole as a skip-when-missing gate, wearing \
         different clothes.\n\n\
         Add each to the `for filter in \\` list in the \"real-client evidence\" step, and \
         install whatever binary it drives in the apt/download steps above it. If it genuinely \
         cannot run there, add it to NOT_RUN_ANYWHERE with the reason — that list may only \
         shrink.",
        missing.join("\n  ")
    );
}

/// The blocking `Test` job must install every client the protocols it compiles will drive.
///
/// This is the one that broke the build. `Test` runs the `CI_PROTOCOL_TESTS` suites, so every
/// real-client test of those protocols *runs* there, hard-failing when
/// its binary is absent. `registry-audit` having the binary is no help: that job is
/// `continue-on-error`, so a green PR says nothing about it.
#[test]
fn ci_feature_clients_are_installed() {
    let text = workflow();

    // `CI_PROTOCOL_TESTS: >-` folds the module filters that follow it, one indentation deeper:
    // `server::tcp:: … client::redis::`. Each names a suite the job runs.
    let start = text
        .find("CI_PROTOCOL_TESTS: >-\n")
        .expect("ci.yml no longer defines CI_PROTOCOL_TESTS");
    let filters: Vec<&str> = text[start..]
        .lines()
        .skip(1)
        .take_while(|l| l.starts_with("    "))
        .flat_map(|l| l.split_whitespace())
        .collect();
    // A suite is named as `real_client_tests` names it: `<p>` for a server, `client/<p>`.
    let features: BTreeSet<String> = filters
        .iter()
        .filter_map(|f| {
            let f = f.trim_end_matches("::");
            f.strip_prefix("server::")
                .map(str::to_string)
                .or_else(|| f.strip_prefix("client::").map(|p| format!("client/{p}")))
        })
        .collect();
    assert!(
        features.len() >= 5,
        "CI_PROTOCOL_TESTS parsed as {features:?}, which is not a suite list — the parse is broken"
    );

    // The `test:` job's own YAML block, so a binary named only in `registry-audit`'s apt line
    // does not read as installed here. That mistake is the whole defect this test covers.
    let job_start = text
        .find("\n  test:\n")
        .expect("ci.yml no longer has a job named `test`");
    // The next job starts at the next two-space-indented key.
    let job_end = text[job_start + 1..]
        .match_indices("\n  ")
        .find(|(i, _)| {
            let rest = &text[job_start + 1 + i + 3..];
            rest.starts_with(|c: char| c.is_ascii_lowercase())
                && rest
                    .split('\n')
                    .next()
                    .is_some_and(|l| l.trim_end().ends_with(':'))
        })
        .map(|(i, _)| i + job_start + 1)
        .unwrap_or(text.len());
    // Comment lines are stripped, and that is not fussiness: the step documents each binary
    // in a `#   kdig  knot-dnsutils  …` table, so a substring search over the raw block matches
    // the *documentation* of a client that is no longer installed. Deleting `knot-dnsutils`
    // from the apt line left this test green until the comments were dropped — a ratchet
    // counting a token instead of the thing, which is the exact failure CLAUDE.md warns about.
    //
    // What is left is the step's commands, so a binary counts as installed only if the job
    // really names it in one: in the apt list, or in the `kdig -V` / `redis-cli --version`
    // presence checks that follow it, which fail the step when the binary is not on PATH.
    let job: String = text[job_start..job_end]
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let job = job.as_str();

    let mut missing = Vec::new();
    for (name, bins) in real_client_tests() {
        let suite = name.split("::").next().unwrap();
        if !features.contains(suite) {
            continue;
        }
        for bin in bins {
            if !job.contains(&bin) {
                let path = match name.strip_prefix("client/") {
                    Some(rest) => format!("client::{rest}"),
                    None => format!("server::{name}"),
                };
                missing.push(format!("{bin}  (driven by {path})"));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "the blocking `Test` job runs the CI_PROTOCOL_TESTS suites, which makes these tests RUN there, and \
         they hard-fail rather than skip when their binary is absent — but the job never \
         installs it:\n\n  {}\n\n\
         Add it to the \"install the third-party clients the CI_PROTOCOL_TESTS suites drive\" step. \
         Do NOT filter the test out of the job instead: a hard-fail gate exists so nobody can \
         quietly run a suite without the client, and a `--skip` list is one more hand-maintained \
         list to go stale.",
        missing.join("\n  ")
    );
}

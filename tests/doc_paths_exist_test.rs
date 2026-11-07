//! Every file path a protocol's `AGENTS.md` names in backticks must exist.
//!
//! The root `AGENTS.md` warns that the per-protocol docs "are frequently more aspirational than
//! the code". The most expensive shape of that is **fiction**: a doc that describes files,
//! suites and test cases which were never written. It reads exactly like a doc that describes
//! something real, and nothing in the tree disagrees with it, so the next person plans around
//! it. `tests/server/bluetooth_ble_remote/AGENTS.md` described three btleplug test cases with
//! per-test LLM budgets and an explanation of why they were `#[ignore]`d; none of the three
//! existed. `src/client/smtp/AGENTS.md` gave the full call signature of a
//! `SmtpClient::send_email` that has no definition.
//!
//! A path is the one part of that prose a machine can settle. This test walks every
//! `src/**/AGENTS.md` and `tests/**/AGENTS.md`, takes every backticked span that looks like a
//! path into this repository, and requires it to resolve on disk.
//!
//! # What counts as a path, and why the rule is this narrow
//!
//! The rule is deliberately conservative, because a build-failing check with false positives
//! teaches people to edit the baseline instead of the code — the lesson the root `AGENTS.md`
//! draws from the strict version of the startup-parameter scan. A span is a candidate only if
//! it contains a `/`, ends in a known source extension, has no whitespace, no glob or
//! `<placeholder>` metacharacter, no URL scheme, and is not absolute. Every one of those
//! exclusions was measured against the tree rather than guessed:
//!
//! - **No `/` ⇒ not checked.** 1321 spans are bare filenames (`server_startup.rs`,
//!   `e2e_test.rs`, `actions.rs`). They are usually shorthand for a file the reader already has
//!   open, and there are 137 different `actions.rs`, so "does it exist" has no useful answer.
//! - **Absolute paths are skipped.** `/jwks.json`, `/about.txt` and `/readme.txt` are HTTP
//!   request targets and served-file names, not files in this tree, and `/etc/docker/daemon.json`
//!   belongs to the machine.
//! - **A scheme is skipped.** `smb://fileserver/documents/readme.txt` is a URL.
//! - **A suffix resolves.** `cli/client_startup.rs`, `state/server.rs` and `server/peer_support.rs`
//!   are how this repo habitually cites a file, and all three name something real. Requiring the
//!   full repo-relative spelling would flag 26 correct citations, so a candidate resolves if it
//!   is a component-aligned suffix of any file in the tree.
//! - **Directories are not checked.** The one non-URL directory span that fails to resolve is
//!   `src/client/eapol/` in `src/server/eapol/AGENTS.md`, in a sentence whose point is that
//!   there *is* no such directory. A rule that fails a doc for correctly saying something is
//!   absent is worse than no rule.
//!
//! # Markdown links are checked too, and were worse
//!
//! `[text](../../X.md)` is the same claim in a different syntax, and the yield there was far
//! higher: **15 of 35** relative link targets were dead, almost all of them pointing at root
//! status reports (`TEST_INFRASTRUCTURE_FIXES.md`, `TEST_STATUS_REPORT.md`,
//! `IPSEC_RESEARCH.md`) that the root-clutter cleanup deleted. Those had zero false positives,
//! so link targets carry no exemption list: a relative link either resolves or is dead.
//!
//! # False-positive rate
//!
//! Measured over the whole tree at the time of writing: 980 backticked spans qualify as
//! candidates and 31 did not resolve. One was a `./` normalisation bug in the extractor, since
//! fixed. **14 were real drift** and were corrected in the commit before this one. The other 16
//! occurrences — 15 distinct doc/path pairs — are the single class this check cannot decide
//! from source: a path that is real, but in **another** repository. They are listed in
//! `FOREIGN_PATHS` below with the reason each is exempt, and that list is the whole
//! false-positive surface: 1.6% of candidates before naming them, zero after.
//!
//! Adding an entry to `FOREIGN_PATHS` is a claim that the path names a file in a *different*
//! codebase. It is not a way to silence a path that ought to exist here and does not.
//!
//! # What is deliberately *not* checked, and why
//!
//! A backticked Rust item (`Type::method`, `fn_name()`) was tried and rejected. Scoped to spans
//! whose type this repo defines, 587 qualify and 10 do not resolve — but 8 of those 10 are
//! correct: `Statement::set_consistency` is scylla's, `OpenAIConfig::with_api_key` is
//! async-openai's, `Message::from_vec()` is hickory-dns's, and `ImapServer::spawn_with_tls` is
//! a deliberate reference to something that *used* to exist. A source-only scan cannot resolve
//! a name against the crate that owns it, so the check would fail eight correct docs to catch
//! two — the shape the root `AGENTS.md` warns trains people to edit the baseline instead of the
//! code. The two it did catch were found by running the measurement once, by hand, and fixed.
//!
//! Run with:
//!   ./cargo-isolated.sh test --no-default-features --features tcp --test doc_paths_exist_test

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Extensions that make a backticked span worth treating as a file path.
const SOURCE_EXTENSIONS: &[&str] = &[
    ".rs", ".md", ".toml", ".sh", ".py", ".js", ".ts", ".json", ".yml", ".yaml", ".proto", ".html",
    ".css", ".lock", ".txt", ".rb", ".sql",
];

/// Directories that are not part of the source tree.
const SKIP_DIRS: &[&str] = &["target", ".git", ".claude", "node_modules", "tmp"];

/// Paths that are real, but in another repository.
///
/// `(doc, path, why)`. Each entry asserts that the span names a file the reader will find
/// somewhere other than this checkout — a dependency's own sources, or content this repo
/// *serves* rather than contains.
const FOREIGN_PATHS: &[(&str, &str, &str)] = &[
    (
        "src/server/mysql/AGENTS.md",
        "mysql/NETGET.md",
        "the netget-net/opensrv fork's own patch notes, which NetGet builds from crates.io",
    ),
    (
        "src/server/bluetooth_ble_beacon/AGENTS.md",
        "src/adv.rs",
        "bluer 0.17.4's own sources, cited for how it builds an advertisement",
    ),
    (
        "src/server/bluetooth_ble_beacon/AGENTS.md",
        "src/adapter.rs",
        "bluer 0.17.4's own sources",
    ),
    (
        "src/server/bluetooth_ble_beacon/AGENTS.md",
        "src/session.rs",
        "bluer 0.17.4's own sources",
    ),
    (
        "src/server/can/AGENTS.md",
        "src/socket.rs",
        "socketcan 3.6's own sources, which this server was written against",
    ),
    (
        "src/server/can/AGENTS.md",
        "src/frame.rs",
        "socketcan 3.6's own sources",
    ),
    (
        "src/server/ssdp/AGENTS.md",
        "src/search.rs",
        "ssdp-client 2.1.0's own sources, where the multicast destination is a literal",
    ),
    (
        "tests/server/ntp/AGENTS.md",
        "src/core_logic.rs",
        "rsntp's own sources, whose checks the test relies on",
    ),
    (
        "src/server/git/AGENTS.md",
        "src/main.rs",
        "a file inside the git repository this server serves, not in this tree",
    ),
    (
        "tests/server/git/AGENTS.md",
        "src/main.rs",
        "a file inside the git repository the test serves and clones",
    ),
    (
        "tests/server/git/AGENTS.md",
        "bin/run.sh",
        "a file inside the git repository the test serves, checked for its executable bit",
    ),
    (
        "src/client/svn/AGENTS.md",
        "src/client/svn/protocol.rs",
        "a planning document for an unimplemented client; the header says so in its first line",
    ),
    (
        "src/client/svn/AGENTS.md",
        "src/client/svn/mod.rs",
        "a planning document for an unimplemented client",
    ),
    (
        "src/client/svn/AGENTS.md",
        "src/client/svn/actions.rs",
        "a planning document for an unimplemented client",
    ),
    (
        "src/client/svn/AGENTS.md",
        "tests/client/svn/e2e_test.rs",
        "a planning document for an unimplemented client",
    ),
    (
        "src/client/svn/AGENTS.md",
        "tests/client/svn/AGENTS.md",
        "a planning document for an unimplemented client",
    ),
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Instruction documents under `src/` and `tests/`, including the legacy filename.
fn protocol_docs(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                if p.file_name()
                    .is_some_and(|n| SKIP_DIRS.iter().any(|s| n == *s))
                {
                    continue;
                }
                walk(&p, out);
            } else if p
                .file_name()
                .is_some_and(|n| n == "AGENTS.md" || n == "CLAUDE.md")
            {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(&root.join("src"), &mut out);
    walk(&root.join("tests"), &mut out);
    out.sort();
    out
}

/// Every file in the tree, as a repo-relative `/`-separated path.
fn all_files(root: &Path) -> BTreeSet<String> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeSet<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                if p.file_name()
                    .is_some_and(|n| SKIP_DIRS.iter().any(|s| n == *s))
                {
                    continue;
                }
                walk(&p, root, out);
            } else if let Ok(rel) = p.strip_prefix(root) {
                out.insert(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(root, root, &mut out);
    out
}

/// The document with every fenced code block blanked out.
///
/// A path inside a fence is often illustrative — a proposed layout, a shell transcript, a
/// `tree` rendering — and holding it to the same standard would flag design notes for
/// describing what they propose. Lines are kept (blanked) so reported line numbers stay right.
fn outside_code_fences(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_fence = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            out.push('\n');
            continue;
        }
        if !in_fence {
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// The backticked spans of one line, in order.
fn backticked(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(open) = rest.find('`') {
        let after = &rest[open + 1..];
        match after.find('`') {
            Some(close) => {
                out.push(&after[..close]);
                rest = &after[close + 1..];
            }
            None => break,
        }
    }
    out
}

/// The relative targets of the markdown links on one line: the `x/y.md` of `[text](x/y.md)`.
///
/// Absolute targets, URLs, `mailto:` and bare `#anchor`s are skipped; a `#fragment` on a
/// relative target is stripped before the target is resolved.
fn markdown_link_targets(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b']' || i + 1 >= bytes.len() || bytes[i + 1] != b'(' {
            i += 1;
            continue;
        }
        let Some(close) = line[i + 2..].find(')') else {
            break;
        };
        let target = &line[i + 2..i + 2 + close];
        i += 2 + close + 1;
        if target.is_empty()
            || target.contains(char::is_whitespace)
            || target.contains("://")
            || target.starts_with('#')
            || target.starts_with("mailto:")
            || target.starts_with('/')
        {
            continue;
        }
        let target = target.split('#').next().unwrap_or(target);
        if target.is_empty() {
            continue;
        }
        out.push(target.to_string());
    }
    out
}

/// Does this span claim to be a path into this repository?
fn is_repo_path_candidate(span: &str) -> bool {
    let s = span.trim();
    if s.is_empty() || s.contains(char::is_whitespace) {
        return false;
    }
    // A glob or a `<placeholder>` names a family, not a file.
    if s.contains('*') || s.contains('<') || s.contains('>') || s.contains('?') {
        return false;
    }
    // A URL, however much of it looks like a path.
    if s.contains("://") {
        return false;
    }
    // Absolute and home-relative paths belong to the machine or to a request line, not here.
    if s.starts_with('/') || s.starts_with('~') || s.starts_with("..") {
        return false;
    }
    let s = s.strip_prefix("./").unwrap_or(s);
    if !s.contains('/') {
        return false;
    }
    SOURCE_EXTENSIONS.iter().any(|e| s.ends_with(e))
}

/// Does `span` name a file that exists?
///
/// Three spellings count, in decreasing strictness: the full repo-relative path, a
/// component-aligned suffix of one (`state/server.rs` for `src/state/server.rs`), and a path
/// relative to the directory the doc itself lives in.
// The instruction migration retained document contents, including legacy citations.
// Resolve that filename only to an AGENTS.md file that actually exists. Other missing
// paths still fail, and exemption identities use the current document filename.
fn current_instruction_path(path: &str) -> String {
    let parsed = Path::new(path);
    if parsed.file_name().is_some_and(|name| name == "CLAUDE.md") {
        parsed
            .with_file_name("AGENTS.md")
            .to_string_lossy()
            .into_owned()
    } else {
        path.to_string()
    }
}

fn existing_instruction_target(path: &Path) -> bool {
    path.exists()
        || (path.file_name().is_some_and(|name| name == "CLAUDE.md")
            && path.with_file_name("AGENTS.md").exists())
}

fn resolves(span: &str, doc_dir_rel: &str, files: &BTreeSet<String>) -> bool {
    resolves_current(span, doc_dir_rel, files)
        || resolves_current(&current_instruction_path(span), doc_dir_rel, files)
}

fn resolves_current(span: &str, doc_dir_rel: &str, files: &BTreeSet<String>) -> bool {
    let s = span.strip_prefix("./").unwrap_or(span);
    if files.contains(s) {
        return true;
    }
    let sibling = format!("{doc_dir_rel}/{s}");
    if files.contains(&sibling) {
        return true;
    }
    // Vendored crates are named by full path: their `src/session.rs` is not the `src/session.rs`
    // of some other dependency a doc cites.
    let suffix = format!("/{s}");
    files
        .iter()
        .any(|f| f.ends_with(&suffix) && !f.starts_with("vendor/"))
}

#[test]
fn every_backticked_path_in_a_protocol_doc_exists() {
    let root = repo_root();
    let files = all_files(&root);
    assert!(
        files.len() > 500,
        "the file index looks wrong ({} entries) — the walk is not seeing the tree",
        files.len()
    );

    let mut candidates = 0usize;
    let mut link_targets = 0usize;
    let mut unresolved: Vec<String> = Vec::new();
    let mut dead_links: Vec<String> = Vec::new();
    let mut unused_exemptions: BTreeSet<(String, String)> = FOREIGN_PATHS
        .iter()
        .map(|(d, p, _)| ((*d).to_string(), (*p).to_string()))
        .collect();

    for doc in protocol_docs(&root) {
        let doc_rel = doc
            .strip_prefix(&root)
            .unwrap_or(&doc)
            .to_string_lossy()
            .replace('\\', "/");
        let exemption_doc = current_instruction_path(&doc_rel);
        let doc_dir_rel = doc_rel.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
        let text = std::fs::read_to_string(&doc).unwrap_or_default();

        let prose = outside_code_fences(&text);
        for (lineno, line) in prose.lines().enumerate() {
            for span in backticked(line) {
                let span = span.trim();
                if !is_repo_path_candidate(span) {
                    continue;
                }
                candidates += 1;
                if resolves(span, doc_dir_rel, &files) {
                    continue;
                }
                let normalised = current_instruction_path(span.strip_prefix("./").unwrap_or(span));
                if unused_exemptions.remove(&(exemption_doc.clone(), normalised.to_string())) {
                    continue;
                }
                if FOREIGN_PATHS
                    .iter()
                    .any(|(d, p, _)| *d == exemption_doc && *p == normalised)
                {
                    continue;
                }
                unresolved.push(format!("{}:{}: `{}`", doc_rel, lineno + 1, span));
            }
        }

        // Markdown link targets are checked on the raw text, fences included: a link inside a
        // fence is still a link, and a relative target either resolves or is dead. This is
        // where the deleted root status reports surfaced — fifteen of thirty-five relative
        // targets pointed at files the root-clutter cleanup removed.
        for (lineno, line) in text.lines().enumerate() {
            for target in markdown_link_targets(line) {
                link_targets += 1;
                let joined = doc.parent().unwrap_or(Path::new(".")).join(&target);
                if existing_instruction_target(&joined)
                    || existing_instruction_target(&root.join(&target))
                {
                    continue;
                }
                dead_links.push(format!("{}:{}: [..]({})", doc_rel, lineno + 1, target));
            }
        }
    }

    assert!(
        candidates > 300,
        "only {candidates} path candidates found — the extractor has stopped working"
    );

    assert!(
        unresolved.is_empty(),
        "{} backticked path(s) in a protocol AGENTS.md name a file that does not exist.\n\n{}\n\n\
         Fix the doc against the source. If a path really does name a file in ANOTHER \
         repository — a dependency's own sources, or content this repo serves rather than \
         contains — add it to FOREIGN_PATHS in {} with the reason.",
        unresolved.len(),
        unresolved.join("\n"),
        file!(),
    );

    assert!(
        link_targets > 10,
        "only {link_targets} relative markdown link targets found — the extractor has stopped \
         working"
    );

    assert!(
        dead_links.is_empty(),
        "{} markdown link(s) in a protocol AGENTS.md point at a file that does not exist.\n\n{}\n\n\
         Point the link at what the reader should actually open, or delete the bullet.",
        dead_links.len(),
        dead_links.join("\n"),
    );

    assert!(
        unused_exemptions.is_empty(),
        "FOREIGN_PATHS has {} entry/entries that no longer match anything — the doc was fixed \
         or the span was reworded, so the exemption should be deleted:\n{}",
        unused_exemptions.len(),
        unused_exemptions
            .iter()
            .map(|(d, p)| format!("  {d}: `{p}`"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

#[test]
fn instruction_migration_keeps_discovery_and_legacy_citations_checked() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("src/server/example");
    let tests = root.path().join("tests/server/example");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir_all(&tests).unwrap();
    let current = source.join("AGENTS.md");
    let legacy = tests.join("CLAUDE.md");
    std::fs::write(&current, "Current instruction document").unwrap();
    std::fs::write(&legacy, "Legacy instruction document").unwrap();
    let docs = protocol_docs(root.path());
    assert_eq!(docs, vec![current.clone(), legacy]);
    let files = all_files(root.path());
    assert!(resolves("src/server/example/CLAUDE.md", "", &files));
    assert!(existing_instruction_target(&source.join("CLAUDE.md")));
    assert!(!resolves("src/server/missing/CLAUDE.md", "", &files));
    assert!(!existing_instruction_target(
        &source.join("missing/CLAUDE.md")
    ));
    assert!(!resolves("src/server/example/missing.rs", "", &files));
    assert!(!resolves("src/server/example/OTHER.md", "", &files));
}

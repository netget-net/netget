//! A server line meant for both the file log and the TUI goes through the `Log` facade.
//!
//! `crate::logging::emit::Log` writes one message to both sinks from one `Level`, so the
//! `[LEVEL]` bracket on the TUI can never disagree with the `tracing` level in `netget.log`,
//! peer-derived text is sanitised once, and DEBUG/TRACE stay off the unbounded status channel by
//! default. The hand-rolled form it replaces is a `tracing` macro beside a
//! `status_tx.send(format!("[LEVEL] …"))`, two strings typed twice that drift apart.
//!
//! # The rule
//!
//! Over every `.rs` file under `src/server/`, count the sends whose message starts with a
//! level bracket — `.send(format!("[INFO] …"` or `.send("[WARN] …"`, across line breaks.
//! Each file may hold at most the count in [`BASELINE`], and the count there may only go down.
//!
//! # What is left in the baseline
//!
//! Each remaining site is a pair whose two halves say *different* things on purpose — most often
//! the file line carries the error detail and the TUI line carries only the decision tag, or the
//! TUI shows a shortened key — or a TUI-only line with no file half. `Log` writes one text to
//! both sinks, so converting those changes what one of the two readers sees; each is a decision
//! for whoever next touches that protocol, not a mechanical edit. A converted pair is one line:
//!
//! ```ignore
//! Log::to(&status_tx).info(format!("POP3 connection {} closed", connection_id));
//! ```
//!
//! **The baseline may only shrink.** When you convert a site, lower its count; a count above
//! what the file holds fails too, so the number stays the truth.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Files that may still hand-roll a `[LEVEL]` send, with the number of sites allowed.
const BASELINE: &[(&str, usize)] = &[
];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src/server") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Number of `.send(` calls whose first argument is a literal (optionally inside `format!(`)
/// that opens with a level bracket.
fn hand_rolled_sends(source: &str) -> usize {
    const LEVELS: &[&str] = &["[ERROR]", "[WARN]", "[INFO]", "[DEBUG]", "[TRACE]"];
    let mut count = 0;
    let mut rest = source;
    while let Some(at) = rest.find(".send(") {
        let mut after = rest[at + ".send(".len()..].trim_start();
        if let Some(inner) = after.strip_prefix("format!(") {
            after = inner.trim_start();
        }
        if let Some(lit) = after.strip_prefix('"') {
            if LEVELS.iter().any(|l| lit.starts_with(l)) {
                count += 1;
            }
        }
        rest = &rest[at + ".send(".len()..];
    }
    count
}

#[test]
fn server_dual_logging_goes_through_the_log_facade() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src/server"), &mut files);
    files.sort();

    let mut found = BTreeMap::new();
    for file in &files {
        let source = std::fs::read_to_string(file).expect("read source");
        let n = hand_rolled_sends(&source);
        if n > 0 {
            let rel = file
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            found.insert(rel, n);
        }
    }

    let baseline: BTreeMap<&str, usize> = BASELINE.iter().copied().collect();
    let mut problems = Vec::new();
    for (file, &n) in &found {
        match baseline.get(file.as_str()) {
            None => problems.push(format!(
                "{file}: {n} hand-rolled `[LEVEL]` send(s); use `Log::to(&status_tx).<level>(…)` \
                 (src/logging/emit.rs) instead of a tracing macro plus a status_tx send"
            )),
            Some(&allowed) if n > allowed => problems.push(format!(
                "{file}: {n} hand-rolled `[LEVEL]` sends, baseline allows {allowed}; convert the \
                 new one to `Log`"
            )),
            Some(&allowed) if n < allowed => problems.push(format!(
                "{file}: {n} hand-rolled `[LEVEL]` sends, baseline still says {allowed}; lower it"
            )),
            _ => {}
        }
    }
    for (file, allowed) in &baseline {
        if !found.contains_key(*file) {
            problems.push(format!(
                "{file}: no hand-rolled `[LEVEL]` sends left (baseline says {allowed}); remove \
                 the entry"
            ));
        }
    }
    assert!(problems.is_empty(), "\n{}\n", problems.join("\n"));
}

#[test]
fn the_scan_sees_every_shape_it_claims_to() {
    let shapes = r#"
        let _ = status_tx.send(format!("[INFO] one {}", x));
        let _ = status_tx.send(format!(
            "[WARN] two {}",
            x
        ));
        let _ = status_clone
            .send(format!("[TRACE] three"));
        let _ = tx.send("[ERROR] four".to_string());
        let _ = tx.send(format!("plain, not counted"));
        Log::to(&status_tx).info("not counted");
    "#;
    assert_eq!(hand_rolled_sends(shapes), 4);
}

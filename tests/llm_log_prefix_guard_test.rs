//! Guard against re-growing the hand-rolled `[LEVEL]` TUI sends that the logging facade
//! is meant to replace.
//!
//! The TUI bracket prefix (`[INFO]`, `[DEBUG]`, …) must be produced by exactly one place:
//! `logging::emit::Log`, which derives it from the same `Level` value it logs to the file
//! with. Anything that hand-writes a `"[LEVEL]"` string literal to send to the TUI can
//! drift from its file-log level (that was the whole bug).
//!
//! Scope: `src/llm/`, where every site goes through the facade: the baseline is empty, so a
//! `[LEVEL]` literal in any `src/llm/` file fails. The rest of `src/` is held by
//! `tests/hand_rolled_dual_logging_ratchet_test.rs`, which parses `.send(...)` calls.
//!
//! (A string-literal count, rather than a `.send(...)` parse, is deliberate: it is robust
//! to multi-line `send(format!(...))` calls and also catches a `[LEVEL]` string built for
//! the TUI a few lines before it is sent.)

use std::collections::HashMap;
use std::path::{Path, PathBuf};

const PREFIXES: [&str; 5] = [
    "\"[ERROR]",
    "\"[WARN]",
    "\"[INFO]",
    "\"[DEBUG]",
    "\"[TRACE]",
];

/// Tolerated counts of `[LEVEL]` string literals per `src/llm/` file (paths relative to
/// `src/llm/`). Empty: every file must be at zero.
fn baseline() -> HashMap<&'static str, usize> {
    HashMap::new()
}

fn count_prefixes(contents: &str) -> usize {
    PREFIXES.iter().map(|p| contents.matches(p).count()).sum()
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_new_raw_level_prefixed_sends_in_src_llm() {
    let llm_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/llm");
    let mut files = Vec::new();
    collect_rs_files(&llm_dir, &mut files);
    assert!(
        !files.is_empty(),
        "found no .rs files under {}",
        llm_dir.display()
    );

    let baseline = baseline();
    let mut failures = Vec::new();

    for file in &files {
        let rel = file
            .strip_prefix(&llm_dir)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let contents = std::fs::read_to_string(file).expect("read source file");
        let count = count_prefixes(&contents);
        let allowed = baseline.get(rel.as_str()).copied().unwrap_or(0);

        if count > allowed {
            failures.push(format!(
                "  src/llm/{rel}: {count} `[LEVEL]` literal(s), baseline is {allowed}. \
                 Route TUI lines through `logging::emit::Log` instead of hand-writing a \
                 `[LEVEL]` prefix (and if you removed some, lower the baseline in this test)."
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "new hand-rolled `[LEVEL]` TUI prefix(es) in src/llm/ (must go through the facade):\n{}",
        failures.join("\n")
    );
}

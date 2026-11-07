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
//! No `.rs` file under `src/server/` may hold a send whose message starts with a level
//! bracket — `.send(format!("[INFO] …"` or `.send("[WARN] …"`, across line breaks. There is no
//! baseline: every server site goes through `Log`.
//!
//! ```ignore
//! Log::to(&status_tx).info(format!("POP3 connection {} closed", connection_id));
//! ```
//!
//! Where the operator and the file need different amounts of detail, write one line both read —
//! the subject, the `decision=` tag and whatever detail is safe on the dashboard — and put what
//! only the file should hold (a full error chain, a payload, a statement that may carry a
//! credential) in a second `Log` DEBUG or TRACE line, which stays in the file:
//!
//! ```ignore
//! let log = Log::to(&status_tx);
//! log.error(format!("POP3 {verb} on connection {id} decision={token}: {}", short(&e)));
//! log.debug(format!("POP3 {verb} on connection {id} LLM error chain: {e:#}"));
//! ```

use std::path::{Path, PathBuf};

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
    // A scan of nothing passes; make sure it read the server tree.
    assert!(
        files.len() > 300,
        "only {} .rs files found under src/server",
        files.len()
    );

    let mut problems = Vec::new();
    for file in &files {
        let source = std::fs::read_to_string(file).expect("read source");
        let n = hand_rolled_sends(&source);
        if n > 0 {
            let rel = file
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            problems.push(format!(
                "{rel}: {n} hand-rolled `[LEVEL]` send(s); use `Log::to(&status_tx).<level>(…)` \
                 (src/logging/emit.rs) instead of a tracing macro plus a status_tx send"
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

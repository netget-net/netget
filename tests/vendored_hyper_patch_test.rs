//! The vendored hyper in `vendor/hyper` is the one Cargo actually builds, and it still
//! carries the browser-build patch.
//!
//! `vendor/hyper` is hyper's crates.io source with one change: `src/common/date.rs` reads
//! JavaScript's clock on wasm32-unknown-unknown instead of calling `SystemTime::now()`, which
//! panics there. Every hyper server calls that cache on its first poll, so without the patch
//! the first HTTP request to any of them kills the browser demo. `vendor/hyper/README.md` has
//! the diff.
//!
//! The patch fails silently in two ways, and this test is the only thing that notices either:
//!
//! - **Cargo stops using it.** `[patch.crates-io]` applies only while the vendored version
//!   satisfies every `hyper = "1.x"` requirement in the graph. When a dependency (or a
//!   `cargo update`) wants a newer hyper, Cargo resolves that one from crates.io, records the
//!   patch under `[[patch.unused]]`, prints one warning and builds fine — natively nothing
//!   changes, and the browser demo is broken again. The locked hyper 1.x must therefore be the
//!   path copy (no `source` line) at exactly the vendored version.
//! - **Someone re-vendors a new hyper and forgets the patch.** The date cache must reach the
//!   clock only through the gated `wasm_now()` on wasm32, and the gated `js-sys` dependency must
//!   still be declared.
//!
//! It reads files only, so it holds at any feature set.

use std::fs;
use std::path::Path;

const WASM: &str = r#"#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]"#;
const NOT_WASM: &str = r#"#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]"#;

fn read(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The `version = "…"` of the `[package]` table of a Cargo manifest.
fn manifest_version(manifest: &str) -> String {
    let mut in_package = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package {
            if let Some(v) = line.strip_prefix("version = ") {
                return v.trim_matches('"').to_string();
            }
        }
    }
    panic!("vendor/hyper/Cargo.toml has no [package] version");
}

/// Every `[[package]]` entry in Cargo.lock named `name`: (version, source line if any).
fn locked_packages(lock: &str, name: &str) -> Vec<(String, Option<String>)> {
    lock.split("[[package]]")
        .skip(1)
        .filter_map(|entry| {
            let field = |key: &str| {
                entry.lines().find_map(|l| {
                    l.strip_prefix(&format!("{key} = "))
                        .map(|v| v.trim_matches('"').to_string())
                })
            };
            (field("name")? == name).then(|| (field("version").unwrap(), field("source")))
        })
        .collect()
}

#[test]
fn cargo_builds_the_vendored_hyper_at_the_vendored_version() {
    let root = read("Cargo.toml");
    // The section header is a line of its own; match the line, not the words, which comments
    // may also contain.
    let patch = root
        .split_once("\n[patch.crates-io]\n")
        .map(|(_, rest)| rest.split("\n[").next().unwrap_or(rest))
        .unwrap_or("");
    assert!(
        patch.lines().any(|l| l.trim() == r#"hyper = { path = "vendor/hyper" }"#),
        "Cargo.toml's [patch.crates-io] must point hyper at vendor/hyper (see vendor/hyper/README.md)"
    );

    let vendored = manifest_version(&read("vendor/hyper/Cargo.toml"));
    let lock = read("Cargo.lock");
    let hyper1: Vec<_> = locked_packages(&lock, "hyper")
        .into_iter()
        .filter(|(v, _)| v.starts_with("1."))
        .collect();
    assert!(!hyper1.is_empty(), "Cargo.lock has no hyper 1.x at all");
    for (version, source) in &hyper1 {
        assert!(
            source.is_none() && *version == vendored,
            "Cargo.lock resolves hyper {version} from {} but vendor/hyper is {vendored}: the \
             browser-build patch is not the hyper being built. If the versions differ, re-vendor \
             hyper {version} and re-apply the patch as vendor/hyper/README.md describes; if they \
             match, the [patch.crates-io] entry is not in effect — restore it and let Cargo \
             rewrite Cargo.lock.",
            source.as_deref().unwrap_or("a path")
        );
    }

    let unused = lock.split("[[patch.unused]]").skip(1).any(|entry| {
        entry
            .lines()
            .take_while(|l| !l.starts_with("[["))
            .any(|l| l.trim() == r#"name = "hyper""#)
    });
    assert!(
        !unused,
        "Cargo.lock lists vendor/hyper under [[patch.unused]]: Cargo is building crates.io's \
         hyper instead. Re-vendor the version it wants and re-apply the patch \
         (vendor/hyper/README.md)."
    );
}

#[test]
fn the_vendored_date_cache_never_calls_system_time_now_on_wasm32() {
    let date = read("vendor/hyper/src/common/date.rs");
    // Everything before the test module is what the library compiles.
    let lib = date.split("#[cfg(test)]").next().unwrap();
    // Comments are blanked rather than dropped, so indices stay line numbers.
    let lines: Vec<&str> = lib
        .lines()
        .map(str::trim)
        .map(|l| if l.starts_with("//") { "" } else { l })
        .collect();

    let calls: Vec<usize> = (0..lines.len())
        .filter(|&i| lines[i].contains("SystemTime::now()"))
        .collect();
    assert!(
        !calls.is_empty(),
        "date.rs no longer calls SystemTime::now(); re-read the patch against it"
    );
    for &i in &calls {
        assert!(
            i > 0 && lines[i - 1] == NOT_WASM,
            "vendor/hyper/src/common/date.rs line {} calls SystemTime::now() without \
             `{NOT_WASM}` above it — that call panics on wasm32-unknown-unknown and kills the \
             browser demo on the first HTTP request. Re-apply the patch (vendor/hyper/README.md).",
            i + 1
        );
        assert!(
            lines.get(i + 1) == Some(&WASM)
                && lines.get(i + 2).is_some_and(|l| l.contains("wasm_now()")),
            "date.rs line {}: the native SystemTime::now() has no wasm32 twin calling wasm_now()",
            i + 1
        );
    }

    let def = lines
        .iter()
        .position(|l| l.starts_with("fn wasm_now() -> SystemTime"))
        .expect("date.rs defines no wasm_now()");
    assert_eq!(
        lines[def - 1],
        WASM,
        "wasm_now() must be compiled for wasm32-unknown-unknown only"
    );
    assert!(
        lines[def + 1].contains("js_sys::Date::now()"),
        "wasm_now() must read JavaScript's wall clock"
    );

    let manifest = read("vendor/hyper/Cargo.toml");
    assert!(
        manifest.contains(
            r#"[target.'cfg(all(target_arch = "wasm32", target_os = "unknown"))'.dependencies.js-sys]"#
        ),
        "vendor/hyper/Cargo.toml no longer declares the wasm32-only js-sys dependency wasm_now() uses"
    );
}

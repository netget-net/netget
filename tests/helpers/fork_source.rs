//! Where Cargo resolved one of NetGet's published forks (`netget-tonic`, `netget-kafka-protocol`,
//! …; github.com/netget-net), so a test can read the patched source it is built against.
//!
//! The forks used to be `vendor/` directories behind `[patch.crates-io]`. A published crate
//! cannot carry a patch, so they are separate crates now, and the source lives in Cargo's
//! registry cache (or wherever a local `[patch]` points while a fork is being changed).

use std::path::PathBuf;

/// The directory holding `package`'s Cargo.toml, as this workspace resolves it.
pub fn fork_dir(package: &str) -> PathBuf {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = std::process::Command::new(cargo)
        .args(["metadata", "--format-version", "1"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo metadata");
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout).expect("metadata JSON");
    let manifest = meta["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|p| p["name"] == package)
        .unwrap_or_else(|| panic!("{package} is not in this workspace's dependency graph"))
        ["manifest_path"]
        .as_str()
        .expect("manifest_path")
        .to_string();
    PathBuf::from(manifest).parent().expect("crate dir").to_path_buf()
}

/// `rel` inside `package`'s source.
pub fn read_fork(package: &str, rel: &str) -> String {
    let path = fork_dir(package).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Every `[[package]]` entry in Cargo.lock named `name`: (version, source line if any).
pub fn locked_packages(name: &str) -> Vec<(String, Option<String>)> {
    let lock = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock"))
        .expect("Cargo.lock");
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

/// The fork is what Cargo builds: `netget-<upstream>` is locked at `version`, and the upstream
/// crate is not in the graph at all, so nothing can reach the unpatched copy.
pub fn assert_fork_is_built(upstream: &str, version: &str) {
    let fork = format!("netget-{upstream}");
    let locked = locked_packages(&fork);
    assert!(!locked.is_empty(), "Cargo.lock has no {fork}");
    assert!(
        locked.iter().all(|(v, _)| v == version),
        "Cargo.lock resolves {fork} at {locked:?}, not {version}: re-check every patch before \
         changing the version"
    );
    let upstream_locked = locked_packages(upstream);
    assert!(
        upstream_locked.is_empty(),
        "Cargo.lock also has upstream {upstream} {upstream_locked:?}: something in the graph \
         depends on the unpatched crate, and NetGet's fork is not the only copy built"
    );
}

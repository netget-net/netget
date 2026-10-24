//! Content the IPFS tests describe to NetGet and write to disk for Kubo and Helia: the same
//! bytes both ways, so their root CIDs can be compared.
// Compiled into every test binary that declares `helpers`; only the libp2p suites use it.
#![allow(dead_code)]
use serde_json::{json, Value};
use std::path::Path;

/// Deterministic bytes that do not repeat, so every chunk is a different block.
pub fn noise(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// A path in a tree on disk: a file's content, or a symlink's target; a directory has neither.
pub type DiskEntry = (String, Option<Vec<u8>>, Option<String>);

/// A tree on disk and the same tree as a description.
pub fn tree() -> (Value, Vec<DiskEntry>) {
    let big = noise(42, 700_000);
    let entries = json!([
        {"name": "a.txt", "text": "hello from a directory\n"},
        {"name": "big.bin", "hex": hex::encode(&big)},
        {"name": "empty.txt", "text": ""},
        {"name": "ünïcode name.txt", "text": "names are UTF-8\n"},
        {"name": "sub", "kind": "dir", "entries": [
            {"name": "nested.txt", "text": "nested\n"},
            {"name": "deeper", "kind": "dir", "entries": [
                {"name": "z", "text": "z"},
            ]},
        ]},
        {"name": "emptydir", "kind": "dir", "entries": []},
        {"name": "link", "kind": "symlink", "target": "a.txt"},
    ]);
    // (path, file content, symlink target); a directory has neither.
    let disk = vec![
        (
            "a.txt".into(),
            Some(b"hello from a directory\n".to_vec()),
            None,
        ),
        ("big.bin".into(), Some(big), None),
        ("empty.txt".into(), Some(Vec::new()), None),
        (
            "ünïcode name.txt".into(),
            Some(b"names are UTF-8\n".to_vec()),
            None,
        ),
        ("sub".into(), None, None),
        ("sub/nested.txt".into(), Some(b"nested\n".to_vec()), None),
        ("sub/deeper".into(), None, None),
        ("sub/deeper/z".into(), Some(b"z".to_vec()), None),
        ("emptydir".into(), None, None),
        ("link".into(), None, Some("a.txt".into())),
    ];
    (json!({"name": "site", "entries": entries}), disk)
}

pub fn write_tree(root: &Path, disk: &[DiskEntry]) {
    std::fs::create_dir_all(root).unwrap();
    for (path, content, target) in disk {
        let p = root.join(path);
        match (content, target) {
            (Some(c), _) => std::fs::write(&p, c).unwrap(),
            (None, Some(t)) => std::os::unix::fs::symlink(t, &p).unwrap(),
            (None, None) => std::fs::create_dir_all(&p).unwrap(),
        }
    }
}

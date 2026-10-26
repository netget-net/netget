//! `netget::server::described_tree` — the FUSE server's tree description: what the model (or
//! a static or script handler) answers for a directory, parsed and committed into the tree
//! every lookup, read and listing is then served from.
//!
//! A description nests (a directory may carry its own `entries`), so the walk is the shape the
//! recursive-decoder rule is about. It is iterative and counts `MAX_TREE_DEPTH`; the corpus's
//! `depth_bomb` nests a hundred directories, past that bound and short of serde_json's own
//! 128-level parse limit, so the walk itself is what refuses it. Hard links (`kind:
//! "hardlink"`, a target path) and extended attributes (`xattrs`) ride in the same answer;
//! `link_bomb` names one file 1100 times (past `MAX_LINKS`) and `xattr_bomb` gives one node 200
//! attributes (past `MAX_XATTRS_PER_NODE`).
//!
//! What is accepted is checked to stay inside every bound: no more entries than the answer
//! bound, no directory deeper than `MAX_TREE_DEPTH`, every file readable from start to end
//! without a panic, its reads never longer than its size; every node's link count equal to the
//! names it is listed under, and no more than `MAX_LINKS`; every node's extended attributes
//! within their name, value, count and tree-wide bounds, each listed one readable. Removing one
//! name of a file with several leaves the inode with one link fewer.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::described_tree::{
    Kind, Tree, XattrMode, DEFAULT_MAX_OVERLAY_BYTES, MAX_ENTRIES_PER_ANSWER, MAX_LINKS,
    MAX_TREE_DEPTH, MAX_XATTRS_PER_NODE, MAX_XATTR_BYTES, MAX_XATTR_NAME_BYTES,
    MAX_XATTR_VALUE_BYTES, ROOT,
};
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    let Ok(answer) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let mut tree = Tree::new(0o755, 1000, 1000, DEFAULT_MAX_OVERLAY_BYTES);
    let Ok(count) = tree.describe(ROOT, &answer) else {
        assert_eq!(
            tree.node_count(),
            1,
            "a refused description commits nothing"
        );
        assert_eq!(tree.hard_links(), 0);
        assert_eq!(tree.xattr_bytes(), 0);
        return;
    };
    assert!(count <= MAX_ENTRIES_PER_ANSWER);
    // Every entry is a node, or another name for one.
    assert_eq!(tree.node_count() + tree.hard_links(), count + 1);
    assert!(tree.xattr_bytes() <= MAX_XATTR_BYTES);
    // Walk what was committed, without recursion, counting each node's names.
    let mut queue = vec![ROOT];
    let mut seen = 0usize;
    let mut names: HashMap<u64, (u32, Kind, String)> = HashMap::new();
    let mut xattr_total = 0usize;
    check_xattrs(&tree, ROOT, &mut xattr_total);
    while let Some(dir) = queue.pop() {
        let Ok(entries) = tree.list(dir) else {
            continue;
        };
        for (ino, kind, name) in entries {
            seen += 1;
            let first = names.entry(ino).or_insert((0, kind, String::new()));
            first.0 += 1;
            if first.0 > 1 {
                continue;
            }
            first.2 = name;
            assert!(tree.depth(ino) <= MAX_TREE_DEPTH);
            check_xattrs(&tree, ino, &mut xattr_total);
            let attr = tree.attr(ino).expect("a listed entry has attributes");
            match kind {
                Kind::Dir => queue.push(ino),
                Kind::Symlink => {
                    tree.readlink(ino).expect("a symlink has a target");
                }
                // A description cannot make FIFOs, sockets or device nodes; only mknod can.
                Kind::Fifo | Kind::Socket | Kind::CharDevice | Kind::BlockDevice => {
                    unreachable!("a description made a {}", kind.name())
                }
                Kind::File => {
                    for offset in [0, attr.size / 2, attr.size.saturating_sub(4096)] {
                        if let Ok(bytes) = tree.read(ino, offset, 65536) {
                            assert!(bytes.len() as u64 <= attr.size.saturating_sub(offset));
                        }
                    }
                }
            }
        }
    }
    assert_eq!(seen, count);
    assert_eq!(
        xattr_total,
        tree.xattr_bytes(),
        "the tree counts what it holds"
    );
    // A non-directory's link count is the number of names it is listed under.
    for (ino, (listed, kind, _)) in &names {
        let nlink = tree.attr(*ino).unwrap().nlink;
        if *kind != Kind::Dir {
            assert_eq!(nlink, *listed, "nlink of inode {ino}");
            assert!(nlink as usize <= MAX_LINKS);
        } else {
            assert_eq!(*listed, 1, "a directory has one name");
        }
    }
    // Mutations within the bounds: a write and a read back, an xattr set and read back, and
    // removing one name of a file that has several.
    let mut linked = None;
    for (ino, (listed, kind, _)) in &names {
        if *kind == Kind::File {
            let size = tree.attr(*ino).unwrap().size;
            if tree.write(*ino, size / 3, b"fuzz").is_ok() {
                assert_eq!(
                    tree.read(*ino, size / 3, 4).ok().as_deref(),
                    Some(&b"fuzz"[..])
                );
            }
            if *listed > 1 && linked.is_none() {
                linked = Some((*ino, *listed));
            }
        }
        if tree
            .setxattr(*ino, "user.fuzz", b"v", XattrMode::Either)
            .is_ok()
        {
            assert_eq!(tree.getxattr(*ino, "user.fuzz").ok(), Some(&b"v"[..]));
        }
    }
    if let Some((ino, listed)) = linked {
        let path = tree.paths(ino).pop().expect("a named file has a path");
        let (dir, name) = path.rsplit_once('/').expect("a path has a slash");
        let parent = resolve(&tree, dir);
        tree.unlink(parent, name)
            .expect("a listed name can be unlinked");
        let after = tree.attr(ino).expect("the inode survives its other names");
        assert_eq!(after.nlink, listed - 1);
        tree.read(ino, 0, 16).ok();
    }
});

/// Check one node's extended attributes against every bound, adding their bytes to `total`.
fn check_xattrs(tree: &Tree, ino: u64, total: &mut usize) {
    let names = tree.xattr_names(ino);
    assert!(names.len() <= MAX_XATTRS_PER_NODE);
    let list = tree.listxattr(ino).expect("a live node lists its xattrs");
    assert_eq!(
        list.len(),
        names.iter().map(|n| n.len() + 1).sum::<usize>(),
        "the list is each name and its NUL"
    );
    for name in names {
        assert!(!name.is_empty() && name.len() <= MAX_XATTR_NAME_BYTES);
        let value = tree.getxattr(ino, &name).expect("a listed xattr reads");
        assert!(value.len() <= MAX_XATTR_VALUE_BYTES);
        *total += name.len() + value.len();
    }
}

/// The directory a path names, from the root.
fn resolve(tree: &Tree, path: &str) -> u64 {
    let mut at = ROOT;
    for c in path.split('/').filter(|c| !c.is_empty()) {
        at = tree.lookup(at, c).expect("a listed path resolves").ino;
    }
    at
}

//! `netget::server::described_tree` — the FUSE server's tree description: what the model (or
//! a static or script handler) answers for a directory, parsed and committed into the tree
//! every lookup, read and listing is then served from.
//!
//! A description nests (a directory may carry its own `entries`), so the walk is the shape the
//! recursive-decoder rule is about. It is iterative and counts `MAX_TREE_DEPTH`; the corpus's
//! `depth_bomb` nests a hundred directories, past that bound and short of serde_json's own
//! 128-level parse limit, so the walk itself is what refuses it. What is accepted is checked to
//! stay inside every bound: no more entries than the answer bound, no directory deeper than
//! `MAX_TREE_DEPTH`, and every file readable from start to end without a panic, its reads never
//! longer than its size.

#![no_main]

use libfuzzer_sys::fuzz_target;
use netget::server::described_tree::{
    Kind, Tree, DEFAULT_MAX_OVERLAY_BYTES, MAX_ENTRIES_PER_ANSWER, MAX_TREE_DEPTH, ROOT,
};

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
        return;
    };
    assert!(count <= MAX_ENTRIES_PER_ANSWER);
    assert_eq!(tree.node_count(), count + 1);
    // Walk what was committed, breadth first, without recursion.
    let mut queue = vec![ROOT];
    let mut seen = 0usize;
    while let Some(dir) = queue.pop() {
        let Ok(entries) = tree.list(dir) else {
            continue;
        };
        for (ino, kind, _) in entries {
            seen += 1;
            assert!(tree.depth(ino) <= MAX_TREE_DEPTH);
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
                    // A write then a read back, inside the overlay's bound.
                    if tree.write(ino, attr.size / 3, b"fuzz").is_ok() {
                        assert_eq!(
                            tree.read(ino, attr.size / 3, 4).ok().as_deref(),
                            Some(&b"fuzz"[..])
                        );
                    }
                }
            }
        }
    }
    assert_eq!(seen, count);
});

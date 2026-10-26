//! Hard links, extended attributes, fallocate and RENAME_EXCHANGE in the described tree,
//! without a kernel: link counts across link, unlink, rename and exchange; one inode under
//! several names in a description; every xattr bound and flag; what each fallocate mode does
//! to the overlay and its cap. Runs on every Unix.
use netget::server::described_tree::*;
use serde_json::json;

fn errno(code: i32) -> Stop {
    Stop::Errno(code)
}

fn tree() -> Tree {
    let mut t = Tree::new(0o755, 1000, 1000, DEFAULT_MAX_OVERLAY_BYTES);
    t.describe(
        ROOT,
        &json!({"entries": [
            {"name": "a.txt", "kind": "file", "text": "alpha\n"},
            {"name": "disk.img", "kind": "file", "size": 16384,
             "extents": [{"offset": 0, "length": 16384, "fill": 171}],
             "errors": [{"offset": 12288, "length": 512, "error": "EIO"}]},
            {"name": "d", "kind": "dir", "entries": [{"name": "inner", "kind": "file", "text": "in"}]},
            {"name": "e", "kind": "dir", "entries": []},
            {"name": "s", "kind": "symlink", "target": "a.txt"}
        ]}),
    )
    .unwrap();
    t
}

fn ino(t: &Tree, parent: u64, name: &str) -> u64 {
    t.lookup(parent, name).unwrap().ino
}

fn nlink(t: &Tree, i: u64) -> u32 {
    t.attr(i).unwrap().nlink
}

// ------------------------------------------------------------------ hard links

#[test]
fn a_hard_link_is_one_inode_under_two_names_and_counts_its_links() {
    let mut t = tree();
    let a = ino(&t, ROOT, "a.txt");
    let d = ino(&t, ROOT, "d");
    let e = ino(&t, ROOT, "e");
    assert_eq!(nlink(&t, a), 1);
    let linked = t.link(a, d, "b.txt").unwrap();
    assert_eq!((linked.ino, linked.nlink), (a, 2));
    assert_eq!(t.lookup(d, "b.txt").unwrap().ino, a);
    assert_eq!(t.hard_links(), 1);
    // A write through one name reads back through the other.
    t.write(a, 0, b"ALPHA").unwrap();
    assert_eq!(t.read(ino(&t, d, "b.txt"), 0, 64).unwrap(), b"ALPHA\n");
    t.link(a, e, "c.txt").unwrap();
    assert_eq!(nlink(&t, a), 3);
    let mut paths = t.paths(a);
    paths.sort();
    assert_eq!(paths, vec!["/a.txt", "/d/b.txt", "/e/c.txt"]);

    // Renaming one name moves only that name; the count stays.
    t.rename(d, "b.txt", ROOT, "b2.txt", false).unwrap();
    assert_eq!(nlink(&t, a), 3);
    assert_eq!(t.lookup(d, "b.txt"), Err(errno(libc::ENOENT)));
    assert_eq!(t.lookup(ROOT, "b2.txt").unwrap().ino, a);
    // Renaming a name onto another name of the same inode does nothing (POSIX).
    t.rename(ROOT, "b2.txt", ROOT, "a.txt", false).unwrap();
    assert_eq!(nlink(&t, a), 3);
    assert_eq!(t.lookup(ROOT, "b2.txt").unwrap().ino, a);

    // Unlinking the first name keeps the inode under the others.
    t.unlink(ROOT, "a.txt").unwrap();
    assert_eq!(nlink(&t, a), 2);
    assert_eq!(t.read(a, 0, 64).unwrap(), b"ALPHA\n");
    assert!(t.attr(a).is_some());
    assert_eq!(t.path(a), "/b2.txt", "the next name becomes the first");
    t.unlink(e, "c.txt").unwrap();
    assert_eq!(nlink(&t, a), 1);
    assert_eq!(t.hard_links(), 0);
    // The last name goes, and the inode with it.
    t.unlink(ROOT, "b2.txt").unwrap();
    assert!(t.attr(a).is_none());
}

#[test]
fn a_replaced_name_loses_one_link_and_the_open_unlinked_case_still_holds() {
    let mut t = tree();
    let a = ino(&t, ROOT, "a.txt");
    let inner = ino(&t, ino(&t, ROOT, "d"), "inner");
    t.link(a, ROOT, "a2").unwrap();
    // A rename over one of a's names: a keeps its other one.
    let d = ino(&t, ROOT, "d");
    t.rename(d, "inner", ROOT, "a2", false).unwrap();
    assert_eq!(nlink(&t, a), 1);
    assert_eq!(t.lookup(ROOT, "a2").unwrap().ino, inner);

    // Open, then remove every name: readable with no links until the last release.
    t.link(a, ROOT, "a3").unwrap();
    t.opened(a);
    t.unlink(ROOT, "a.txt").unwrap();
    assert_eq!(nlink(&t, a), 1);
    t.unlink(ROOT, "a3").unwrap();
    assert_eq!(nlink(&t, a), 0);
    assert_eq!(t.read(a, 0, 64).unwrap(), b"alpha\n");
    // Nothing names it, so nothing can link to it.
    assert_eq!(t.check_link(a, ROOT, "back"), Err(errno(libc::ENOENT)));
    t.released(a);
    assert!(t.attr(a).is_none());
}

#[test]
fn link_refuses_what_posix_refuses() {
    let mut t = tree();
    let a = ino(&t, ROOT, "a.txt");
    let d = ino(&t, ROOT, "d");
    let s = ino(&t, ROOT, "s");
    assert_eq!(t.link(d, ROOT, "d2"), Err(errno(libc::EPERM)));
    assert_eq!(t.link(a, ROOT, "s"), Err(errno(libc::EEXIST)));
    assert_eq!(
        t.link(a, ROOT, &"x".repeat(256)),
        Err(errno(libc::ENAMETOOLONG))
    );
    assert_eq!(t.link(a, a, "x"), Err(errno(libc::ENOTDIR)));
    assert_eq!(t.link(999_999, ROOT, "x"), Err(errno(libc::ENOENT)));
    // A symlink may have hard links (link(2) does not follow it).
    assert_eq!(t.link(s, ROOT, "s2").unwrap().nlink, 2);
    // A FIFO too.
    let fifo = t.mknod(ROOT, "p", Kind::Fifo, 0o644, 0, 0, 0).unwrap().ino;
    assert_eq!(t.link(fifo, d, "p2").unwrap().nlink, 2);
}

#[test]
fn a_file_has_at_most_max_links_names_and_the_tree_at_most_max_hard_links() {
    let mut t = Tree::new(0o755, 0, 0, DEFAULT_MAX_OVERLAY_BYTES);
    t.describe(ROOT, &json!({"entries": [{"name": "f", "kind": "file"}]}))
        .unwrap();
    let f = ino(&t, ROOT, "f");
    for i in 1..MAX_LINKS {
        t.link(f, ROOT, &format!("l{i}")).unwrap();
    }
    assert_eq!(nlink(&t, f) as usize, MAX_LINKS);
    assert_eq!(t.link(f, ROOT, "one-more"), Err(errno(libc::EMLINK)));
    assert_eq!(t.lookup(ROOT, "one-more"), Err(errno(libc::ENOENT)));

    // The tree-wide bound: files each linked up to MAX_LINKS, spread over directories.
    let mut t = Tree::new(0o755, 0, 0, DEFAULT_MAX_OVERLAY_BYTES);
    t.describe(ROOT, &json!({"entries": []})).unwrap();
    let mut made = 0usize;
    let mut file = 0;
    'outer: for dir in 0.. {
        let d = t.mkdir(ROOT, &format!("d{dir}"), 0o755, 0, 0).unwrap().ino;
        for _ in 0..(MAX_DIR_ENTRIES / MAX_LINKS) {
            let f = t.create(d, &format!("f{file}"), 0o644, 0, 0).unwrap().ino;
            file += 1;
            for i in 1..MAX_LINKS {
                if made == MAX_HARD_LINKS {
                    assert_eq!(
                        t.check_link(f, d, &format!("x{i}")),
                        Err(errno(libc::ENOSPC))
                    );
                    break 'outer;
                }
                t.link(f, d, &format!("f{file}-{i}")).unwrap();
                made += 1;
            }
        }
    }
    assert_eq!(t.hard_links(), MAX_HARD_LINKS);
}

#[test]
fn a_description_declares_hard_links_by_path() {
    let mut t = Tree::new(0o755, 0, 0, DEFAULT_MAX_OVERLAY_BYTES);
    let n = t
        .describe(
            ROOT,
            &json!({"entries": [
                // Before its target in the answer, and into a nested directory.
                {"name": "early", "kind": "hardlink", "target": "/docs/guide.md"},
                {"name": "docs", "kind": "dir", "entries": [
                    {"name": "guide.md", "kind": "file", "text": "# Guide\n", "mode": 384},
                    {"name": "again", "kind": "hardlink", "target": "/docs/guide.md"}
                ]},
                {"name": "lazy", "kind": "dir"}
            ]}),
        )
        .unwrap();
    assert_eq!(n, 5);
    assert_eq!(t.node_count() + t.hard_links(), n + 1);
    let docs = ino(&t, ROOT, "docs");
    let guide = t.lookup(docs, "guide.md").unwrap();
    assert_eq!(guide.nlink, 3);
    assert_eq!(t.lookup(ROOT, "early").unwrap().ino, guide.ino);
    assert_eq!(t.lookup(docs, "again").unwrap().perm, 0o600);
    // A later description may name a file described before it.
    let lazy = ino(&t, ROOT, "lazy");
    t.describe(
        lazy,
        &json!({"entries": [{"name": "g", "kind": "hardlink", "target": "/docs/guide.md"}]}),
    )
    .unwrap();
    assert_eq!(nlink(&t, guide.ino), 4);
    assert_eq!(t.read(ino(&t, lazy, "g"), 0, 64).unwrap(), b"# Guide\n");
}

#[test]
fn a_broken_hard_link_description_is_refused_whole() {
    let bad = [
        // Nothing there, or nothing described there yet.
        json!({"entries": [{"name": "l", "kind": "hardlink", "target": "/missing"}]}),
        json!({"entries": [{"name": "d", "kind": "dir"},
                           {"name": "l", "kind": "hardlink", "target": "/d/x"}]}),
        // A directory, another hard link, a relative path, a path with '..'.
        json!({"entries": [{"name": "d", "kind": "dir", "entries": []},
                           {"name": "l", "kind": "hardlink", "target": "/d"}]}),
        json!({"entries": [{"name": "f", "kind": "file"},
                           {"name": "l", "kind": "hardlink", "target": "/f"},
                           {"name": "m", "kind": "hardlink", "target": "/l"}]}),
        json!({"entries": [{"name": "f", "kind": "file"},
                           {"name": "l", "kind": "hardlink", "target": "f"}]}),
        json!({"entries": [{"name": "f", "kind": "file"},
                           {"name": "l", "kind": "hardlink", "target": "/../f"}]}),
        // A hard link names its target only.
        json!({"entries": [{"name": "f", "kind": "file"},
                           {"name": "l", "kind": "hardlink", "target": "/f", "text": "x"}]}),
        json!({"entries": [{"name": "f", "kind": "file"},
                           {"name": "l", "kind": "hardlink", "target": "/f", "mode": 420}]}),
        json!({"entries": [{"name": "f", "kind": "file"},
                           {"name": "l", "kind": "hardlink"}]}),
    ];
    for answer in bad {
        let mut t = Tree::new(0o755, 0, 0, DEFAULT_MAX_OVERLAY_BYTES);
        assert!(t.describe(ROOT, &answer).is_err(), "refused: {answer}");
        assert_eq!(t.node_count(), 1, "nothing committed from {answer}");
        assert_eq!(t.hard_links(), 0);
    }
    // MAX_LINKS names for one file in one answer is fine; one more is refused.
    let mut entries = vec![json!({"name": "f", "kind": "file"})];
    for i in 1..MAX_LINKS {
        entries.push(json!({"name": format!("l{i}"), "kind": "hardlink", "target": "/f"}));
    }
    check_description(&json!({ "entries": entries })).unwrap();
    entries.push(json!({"name": "over", "kind": "hardlink", "target": "/f"}));
    let err = check_description(&json!({ "entries": entries })).unwrap_err();
    assert!(err.to_string().contains("names"), "{err}");
}

#[test]
fn removing_a_subtree_keeps_a_file_linked_from_outside_it() {
    let mut t = tree();
    let a = ino(&t, ROOT, "a.txt");
    let d = ino(&t, ROOT, "d");
    let inner = ino(&t, d, "inner");
    t.link(a, d, "a-in-d").unwrap();
    t.link(inner, ROOT, "inner-outside").unwrap();
    let removed = t.remove_subtree(ROOT, "d").unwrap();
    assert!(removed.contains(&d));
    assert!(!removed.contains(&a) && !removed.contains(&inner));
    assert_eq!(nlink(&t, a), 1);
    assert_eq!(nlink(&t, inner), 1);
    assert_eq!(t.path(inner), "/inner-outside");
    assert_eq!(t.read(inner, 0, 8).unwrap(), b"in");
    assert_eq!(t.hard_links(), 0);
}

// ------------------------------------------------------------------ RENAME_EXCHANGE

#[test]
fn exchange_swaps_two_entries_and_refuses_what_it_must() {
    let mut t = tree();
    let a = ino(&t, ROOT, "a.txt");
    let d = ino(&t, ROOT, "d");
    let e = ino(&t, ROOT, "e");
    let inner = ino(&t, d, "inner");
    // A file and a directory swap places.
    t.exchange(ROOT, "a.txt", ROOT, "e").unwrap();
    assert_eq!(t.lookup(ROOT, "a.txt").unwrap().ino, e);
    assert_eq!(t.lookup(ROOT, "e").unwrap().ino, a);
    assert_eq!(t.path(a), "/e");
    assert_eq!(t.path(e), "/a.txt");
    // Across directories.
    t.exchange(d, "inner", ROOT, "e").unwrap();
    assert_eq!(t.path(inner), "/e");
    assert_eq!(t.path(a), "/d/inner");
    assert_eq!(t.read(a, 0, 64).unwrap(), b"alpha\n");
    // Both must exist; a directory cannot land inside itself.
    assert_eq!(
        t.exchange(ROOT, "nope", ROOT, "e"),
        Err(errno(libc::ENOENT))
    );
    assert_eq!(t.exchange(ROOT, "d", d, "inner"), Err(errno(libc::EINVAL)));
    // Two names of one inode: nothing to do.
    t.link(inner, ROOT, "e2").unwrap();
    t.exchange(ROOT, "e", ROOT, "e2").unwrap();
    assert_eq!(nlink(&t, inner), 2);
    // A hard-linked file's names follow the swap.
    t.exchange(ROOT, "e2", ROOT, "s").unwrap();
    let mut paths = t.paths(inner);
    paths.sort();
    assert_eq!(paths, vec!["/e", "/s"]);
}

// ------------------------------------------------------------------ extended attributes

#[test]
fn xattrs_are_described_on_any_node_and_read_back() {
    let mut t = Tree::new(0o755, 0, 0, DEFAULT_MAX_OVERLAY_BYTES);
    t.describe(
        ROOT,
        &json!({
            "xattrs": [{"name": "user.root", "text": "top"}],
            "entries": [
                {"name": "f", "kind": "file", "xattrs": [
                    {"name": "user.mime_type", "text": "text/plain"},
                    {"name": "user.bin", "hex": "00ff10"},
                    {"name": "user.empty"},
                    {"name": "trusted.t", "text": "1"},
                    {"name": "security.s", "text": "2"}]},
                {"name": "d", "kind": "dir", "xattrs": [{"name": "user.d", "text": "dir"}]},
                {"name": "s", "kind": "symlink", "target": "f", "xattrs": [{"name": "trusted.l", "text": "x"}]}
            ]
        }),
    )
    .unwrap();
    assert_eq!(t.getxattr(ROOT, "user.root").unwrap(), b"top");
    let f = ino(&t, ROOT, "f");
    assert_eq!(t.getxattr(f, "user.mime_type").unwrap(), b"text/plain");
    assert_eq!(t.getxattr(f, "user.bin").unwrap(), [0, 0xff, 0x10]);
    assert_eq!(t.getxattr(f, "user.empty").unwrap(), b"");
    assert_eq!(t.getxattr(f, "user.nope"), Err(errno(libc::ENODATA)));
    assert_eq!(
        t.getxattr(f, "system.posix_acl_access"),
        Err(errno(libc::EOPNOTSUPP))
    );
    assert_eq!(
        t.listxattr(f).unwrap(),
        b"security.s\0trusted.t\0user.bin\0user.empty\0user.mime_type\0"
    );
    assert_eq!(t.getxattr(ino(&t, ROOT, "d"), "user.d").unwrap(), b"dir");
    assert_eq!(t.getxattr(ino(&t, ROOT, "s"), "trusted.l").unwrap(), b"x");
    // Names and values: 9+3, 14+10, 8+3, 10+0, 9+1, 10+1, 6+3, 9+1.
    assert_eq!(t.xattr_bytes(), 97);
    // A hard link shares them.
    t.link(f, ROOT, "g").unwrap();
    assert_eq!(
        t.getxattr(ino(&t, ROOT, "g"), "user.bin").unwrap(),
        [0, 0xff, 0x10]
    );
}

#[test]
fn setxattr_honours_create_and_replace_and_every_bound() {
    let mut t = tree();
    let a = ino(&t, ROOT, "a.txt");
    // XATTR_REPLACE needs it to exist; XATTR_CREATE needs it not to.
    assert_eq!(
        t.setxattr(a, "user.k", b"v", XattrMode::Replace),
        Err(errno(libc::ENODATA))
    );
    t.setxattr(a, "user.k", b"v1", XattrMode::Create).unwrap();
    assert_eq!(
        t.setxattr(a, "user.k", b"v2", XattrMode::Create),
        Err(errno(libc::EEXIST))
    );
    assert_eq!(t.getxattr(a, "user.k").unwrap(), b"v1");
    t.setxattr(a, "user.k", b"v22", XattrMode::Replace).unwrap();
    t.setxattr(a, "user.k", b"v333", XattrMode::Either).unwrap();
    assert_eq!(t.getxattr(a, "user.k").unwrap(), b"v333");
    assert_eq!(t.xattr_bytes(), "user.k".len() + 4);
    // Names: the namespace, 255 bytes, never empty.
    let long = format!("user.{}", "n".repeat(MAX_XATTR_NAME_BYTES - 5));
    t.setxattr(a, &long, b"", XattrMode::Either).unwrap();
    assert_eq!(
        t.setxattr(a, &format!("{long}x"), b"", XattrMode::Either),
        Err(errno(libc::ERANGE))
    );
    assert_eq!(
        t.setxattr(a, "system.x", b"", XattrMode::Either),
        Err(errno(libc::EOPNOTSUPP))
    );
    assert_eq!(
        t.setxattr(a, "user.", b"", XattrMode::Either),
        Err(errno(libc::EOPNOTSUPP))
    );
    assert_eq!(
        t.setxattr(a, "", b"", XattrMode::Either),
        Err(errno(libc::EINVAL))
    );
    // Values: 64 KiB.
    let big = vec![7u8; MAX_XATTR_VALUE_BYTES];
    t.setxattr(a, "user.big", &big, XattrMode::Either).unwrap();
    assert_eq!(
        t.getxattr(a, "user.big").unwrap().len(),
        MAX_XATTR_VALUE_BYTES
    );
    assert_eq!(
        t.setxattr(
            a,
            "user.bigger",
            &[0; MAX_XATTR_VALUE_BYTES + 1],
            XattrMode::Either
        ),
        Err(errno(libc::E2BIG))
    );
    // Removal: ENODATA for a name that is not there; it frees its bytes.
    let before = t.xattr_bytes();
    t.removexattr(a, "user.big").unwrap();
    assert_eq!(
        t.xattr_bytes(),
        before - "user.big".len() - MAX_XATTR_VALUE_BYTES
    );
    assert_eq!(t.removexattr(a, "user.big"), Err(errno(libc::ENODATA)));
    assert_eq!(t.getxattr(a, "user.big"), Err(errno(libc::ENODATA)));

    // MAX_XATTRS_PER_NODE on one node; one more is ENOSPC, and replacing one is still fine.
    let b = t.create(ROOT, "b", 0o644, 0, 0).unwrap().ino;
    for i in 0..MAX_XATTRS_PER_NODE {
        t.setxattr(b, &format!("user.{i}"), b"x", XattrMode::Either)
            .unwrap();
    }
    assert_eq!(
        t.setxattr(b, "user.over", b"x", XattrMode::Either),
        Err(errno(libc::ENOSPC))
    );
    t.setxattr(b, "user.0", b"y", XattrMode::Replace).unwrap();
    // Unlinking the file frees everything it held.
    let held = t.xattr_bytes();
    t.unlink(ROOT, "b").unwrap();
    assert!(t.xattr_bytes() < held);
}

#[test]
fn the_tree_wide_xattr_bound_holds_for_sets_and_descriptions() {
    let mut t = tree();
    let a = ino(&t, ROOT, "a.txt");
    let d = ino(&t, ROOT, "d");
    let value = vec![1u8; MAX_XATTR_VALUE_BYTES];
    let mut set = 0;
    // Fill the budget with 64 KiB values over two nodes.
    loop {
        let target = if set < MAX_XATTRS_PER_NODE { a } else { d };
        match t.setxattr(target, &format!("user.v{set}"), &value, XattrMode::Either) {
            Ok(()) => set += 1,
            Err(e) => {
                assert_eq!(e, errno(libc::ENOSPC));
                break;
            }
        }
    }
    assert!(
        set > MAX_XATTRS_PER_NODE,
        "the budget, not the count, stopped it"
    );
    assert!(t.xattr_bytes() <= MAX_XATTR_BYTES);
    assert!(t.xattr_bytes() + MAX_XATTR_VALUE_BYTES + 16 > MAX_XATTR_BYTES);
    assert_eq!(
        t.getxattr(d, &format!("user.v{set}")),
        Err(errno(libc::ENODATA))
    );
    // Removing one makes room again for one of the same size.
    t.removexattr(a, "user.v100").unwrap();
    t.setxattr(d, "user.v100", &value, XattrMode::Create)
        .unwrap();
    // A description past the budget is refused whole.
    let mut t2 = Tree::new(0o755, 0, 0, DEFAULT_MAX_OVERLAY_BYTES);
    let hexed = "ab".repeat(MAX_XATTR_VALUE_BYTES);
    let entries: Vec<_> = (0..(MAX_XATTR_BYTES / MAX_XATTR_VALUE_BYTES + 1))
        .map(|i| json!({"name": format!("f{i}"), "kind": "file", "xattrs": [{"name": "user.v", "hex": hexed}]}))
        .collect();
    assert!(t2.describe(ROOT, &json!({ "entries": entries })).is_err());
    assert_eq!(t2.node_count(), 1);
    assert_eq!(t2.xattr_bytes(), 0);
}

#[test]
fn a_broken_xattr_description_is_refused_whole() {
    let too_many: Vec<_> = (0..=MAX_XATTRS_PER_NODE)
        .map(|i| json!({"name": format!("user.{i}"), "text": "x"}))
        .collect();
    let bad = [
        json!({"entries": [{"name": "f", "kind": "file", "xattrs": too_many}]}),
        json!({"entries": [{"name": "f", "kind": "file", "xattrs": [{"name": "nonamespace", "text": "x"}]}]}),
        json!({"entries": [{"name": "f", "kind": "file", "xattrs": [{"name": "system.posix_acl_access"}]}]}),
        json!({"entries": [{"name": "f", "kind": "file", "xattrs": [{"name": format!("user.{}", "n".repeat(251))}]}]}),
        json!({"entries": [{"name": "f", "kind": "file", "xattrs": [{"name": "user.a"}, {"name": "user.a"}]}]}),
        json!({"entries": [{"name": "f", "kind": "file", "xattrs": [{"name": "user.a", "text": "x", "hex": "00"}]}]}),
        json!({"entries": [{"name": "f", "kind": "file", "xattrs": [{"name": "user.a", "hex": "zz"}]}]}),
        json!({"entries": [{"name": "f", "kind": "file", "xattrs": [{"name": "user.a", "text": "x".repeat(MAX_XATTR_VALUE_BYTES + 1)}]}]}),
        json!({"entries": [{"name": "f", "kind": "file", "xattrs": {"user.a": "x"}}]}),
        json!({"entries": [{"name": "f", "kind": "file"}, {"name": "l", "kind": "hardlink", "target": "/f",
               "xattrs": [{"name": "user.a"}]}]}),
        json!({"xattrs": too_many, "entries": []}),
    ];
    for answer in bad {
        let mut t = Tree::new(0o755, 0, 0, DEFAULT_MAX_OVERLAY_BYTES);
        assert!(
            t.describe(ROOT, &answer).is_err(),
            "refused: {}",
            answer.to_string().chars().take(200).collect::<String>()
        );
        assert_eq!(t.node_count(), 1);
        assert_eq!(t.xattr_bytes(), 0);
        assert_eq!(t.listxattr(ROOT).unwrap(), b"");
    }
}

// ------------------------------------------------------------------ fallocate

#[test]
fn fallocate_modes_are_read_from_linux_bits() {
    assert_eq!(
        Allocation::from_mode(0),
        Some(Allocation::Allocate { keep_size: false })
    );
    assert_eq!(
        Allocation::from_mode(FALLOC_KEEP_SIZE),
        Some(Allocation::Allocate { keep_size: true })
    );
    assert_eq!(
        Allocation::from_mode(FALLOC_PUNCH_HOLE | FALLOC_KEEP_SIZE),
        Some(Allocation::PunchHole)
    );
    assert_eq!(
        Allocation::from_mode(FALLOC_ZERO_RANGE),
        Some(Allocation::ZeroRange { keep_size: false })
    );
    assert_eq!(
        Allocation::from_mode(FALLOC_ZERO_RANGE | FALLOC_KEEP_SIZE),
        Some(Allocation::ZeroRange { keep_size: true })
    );
    // A punch without KEEP_SIZE, COLLAPSE_RANGE, INSERT_RANGE, UNSHARE_RANGE, combinations.
    for mode in [
        FALLOC_PUNCH_HOLE,
        0x08,
        0x08 | FALLOC_KEEP_SIZE,
        0x20,
        0x40,
        FALLOC_PUNCH_HOLE | FALLOC_ZERO_RANGE | FALLOC_KEEP_SIZE,
    ] {
        assert_eq!(Allocation::from_mode(mode), None, "mode {mode:#x}");
    }
}

#[test]
fn allocate_reserves_the_range_and_grows_the_file_unless_keep_size() {
    let mut t = tree();
    let f = t.create(ROOT, "new", 0o644, 0, 0).unwrap().ino;
    t.fallocate(f, 0, 10_000, Allocation::Allocate { keep_size: false })
        .unwrap();
    assert_eq!(t.size(f), Some(10_000));
    assert_eq!(t.overlay_bytes(), 3 * PAGE, "three pages reserved");
    assert_eq!(t.read(f, 0, 20_000).unwrap(), vec![0; 10_000]);
    // Writing into reserved pages costs nothing more.
    t.write(f, 5000, b"hello").unwrap();
    assert_eq!(t.overlay_bytes(), 3 * PAGE);
    // KEEP_SIZE past the end reserves without growing; the blocks show it.
    t.fallocate(
        f,
        10_000,
        2 * PAGE,
        Allocation::Allocate { keep_size: true },
    )
    .unwrap();
    assert_eq!(t.size(f), Some(10_000));
    assert_eq!(t.overlay_bytes(), 5 * PAGE);
    assert_eq!(t.attr(f).unwrap().blocks, 5 * PAGE / 512);
    // Over described content: the bytes stay as described.
    let disk = ino(&t, ROOT, "disk.img");
    t.fallocate(disk, 0, 100, Allocation::Allocate { keep_size: false })
        .unwrap();
    assert_eq!(t.size(disk), Some(16384));
    assert_eq!(t.read(disk, 0, 4).unwrap(), [171; 4]);
    // EFBIG past the file bound, EINVAL for nothing, EINVAL for a directory or symlink.
    assert_eq!(
        t.fallocate(
            f,
            MAX_FILE_SIZE,
            1,
            Allocation::Allocate { keep_size: false }
        ),
        Err(errno(libc::EFBIG))
    );
    assert_eq!(
        t.fallocate(f, u64::MAX, 2, Allocation::Allocate { keep_size: false }),
        Err(errno(libc::EFBIG))
    );
    assert_eq!(
        t.fallocate(f, 0, 0, Allocation::Allocate { keep_size: false }),
        Err(errno(libc::EINVAL))
    );
    assert_eq!(
        t.fallocate(
            ino(&t, ROOT, "d"),
            0,
            1,
            Allocation::Allocate { keep_size: false }
        ),
        Err(errno(libc::EISDIR))
    );
}

#[test]
fn a_punched_hole_reads_as_zeroes_and_keeps_the_size() {
    let mut t = tree();
    let disk = ino(&t, ROOT, "disk.img");
    // A whole page and parts of its neighbours, over described bytes.
    t.fallocate(disk, 4000, 4096 + 200, Allocation::PunchHole)
        .unwrap();
    let all = t.read(disk, 0, 12288).unwrap();
    assert!(all[..4000].iter().all(|b| *b == 171));
    assert!(all[4000..8296].iter().all(|b| *b == 0), "the range is zero");
    assert!(all[8296..].iter().all(|b| *b == 171));
    assert_eq!(t.size(disk), Some(16384));
    // Three pages took overlay: the described bytes beneath had to be hidden.
    assert_eq!(t.overlay_bytes(), 3 * PAGE);
    // Over a failing region the hole reads, as an overwrite would.
    t.fallocate(disk, 12288, 512, Allocation::PunchHole)
        .unwrap();
    assert_eq!(t.read(disk, 12288, 512).unwrap(), vec![0; 512]);
    // Past the end nothing happens.
    t.fallocate(disk, 20_000, 100, Allocation::PunchHole)
        .unwrap();
    assert_eq!(t.size(disk), Some(16384));

    // On a written file with nothing described beneath: whole pages are given back.
    let f = t.create(ROOT, "w", 0o644, 0, 0).unwrap().ino;
    t.write(f, 0, &vec![9u8; 3 * PAGE as usize]).unwrap();
    let before = t.overlay_bytes();
    t.fallocate(f, PAGE, PAGE, Allocation::PunchHole).unwrap();
    assert_eq!(t.overlay_bytes(), before - PAGE, "the middle page is freed");
    let back = t.read(f, 0, 3 * PAGE as u32).unwrap();
    assert!(back[..PAGE as usize].iter().all(|b| *b == 9));
    assert!(back[PAGE as usize..2 * PAGE as usize]
        .iter()
        .all(|b| *b == 0));
    assert!(back[2 * PAGE as usize..].iter().all(|b| *b == 9));
    // A partial page keeps its page and zeroes only the range.
    t.fallocate(f, 10, 5, Allocation::PunchHole).unwrap();
    assert_eq!(t.read(f, 8, 9).unwrap(), [9, 9, 0, 0, 0, 0, 0, 9, 9]);
    assert_eq!(t.size(f), Some(3 * PAGE));
}

#[test]
fn zero_range_zeroes_and_reserves_and_grows_unless_keep_size() {
    let mut t = tree();
    let a = ino(&t, ROOT, "a.txt");
    t.fallocate(a, 2, 2, Allocation::ZeroRange { keep_size: false })
        .unwrap();
    assert_eq!(t.read(a, 0, 64).unwrap(), b"al\0\0a\n");
    t.fallocate(a, 4, 100, Allocation::ZeroRange { keep_size: true })
        .unwrap();
    assert_eq!(t.size(a), Some(6));
    assert_eq!(t.read(a, 0, 64).unwrap(), b"al\0\0\0\0");
    t.fallocate(a, 4, 100, Allocation::ZeroRange { keep_size: false })
        .unwrap();
    assert_eq!(t.size(a), Some(104));
    assert_eq!(t.read(a, 0, 200).unwrap(), {
        let mut v = b"al".to_vec();
        v.resize(104, 0);
        v
    });
}

#[test]
fn fallocate_past_the_overlay_cap_is_enospc_and_changes_nothing() {
    let mut t = Tree::new(0o755, 0, 0, 16 * PAGE);
    t.describe(
        ROOT,
        &json!({"entries": [{"name": "big", "kind": "file", "size": 65536 * 2,
                             "extents": [{"offset": 0, "length": 131072, "fill": 1}]}]}),
    )
    .unwrap();
    let big = ino(&t, ROOT, "big");
    let f = t.create(ROOT, "f", 0o644, 0, 0).unwrap().ino;
    // 17 pages do not fit in 16.
    assert_eq!(
        t.fallocate(f, 0, 17 * PAGE, Allocation::Allocate { keep_size: false }),
        Err(errno(libc::ENOSPC))
    );
    assert_eq!(t.size(f), Some(0));
    assert_eq!(t.overlay_bytes(), 0);
    // Punching 17 pages of described content needs 17 zeroed pages: refused, unchanged.
    assert_eq!(
        t.fallocate(big, 0, 17 * PAGE, Allocation::PunchHole),
        Err(errno(libc::ENOSPC))
    );
    assert_eq!(t.read(big, 0, 4).unwrap(), [1; 4]);
    assert_eq!(
        t.fallocate(f, 0, 17 * PAGE, Allocation::ZeroRange { keep_size: true }),
        Err(errno(libc::ENOSPC))
    );
    // 16 fit exactly, and then not one more byte can be written to a new page.
    t.fallocate(f, 0, 16 * PAGE, Allocation::Allocate { keep_size: false })
        .unwrap();
    assert_eq!(t.overlay_bytes(), 16 * PAGE);
    assert_eq!(t.write(big, 0, b"x"), Err(errno(libc::ENOSPC)));
    // Writing into the reserved pages still works.
    t.write(f, 16 * PAGE - 1, b"z").unwrap();
    // Unlinking frees it all.
    t.unlink(ROOT, "f").unwrap();
    assert_eq!(t.overlay_bytes(), 0);
}

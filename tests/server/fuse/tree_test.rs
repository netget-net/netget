//! The described tree behind the FUSE server, without a kernel: descriptions (nested, lazy,
//! refused whole when any part breaks a bound), reads of text/hex/fill/extents and failing
//! regions, and the overlay every accepted change lands in. Runs on every Unix.
use netget::server::described_tree::*;
use serde_json::json;

fn errno(code: i32) -> Stop {
    Stop::Errno(code)
}

fn described() -> Tree {
    let mut t = Tree::new(0o755, 1000, 1000, DEFAULT_MAX_OVERLAY_BYTES);
    let n = t
        .describe(
            ROOT,
            &json!({"entries": [
                {"name": "README.txt", "kind": "file", "text": "hello\n", "mode": 420, "mtime": 1700000000},
                {"name": "disk.img", "kind": "file", "size": 12288,
                 "extents": [{"offset": 0, "hex": "deadbeef"}, {"offset": 4096, "length": 4096, "fill": 171}],
                 "errors": [{"offset": 8192, "length": 512, "error": "EIO"}]},
                {"name": "docs", "kind": "dir", "entries": [
                    {"name": "a.md", "kind": "file", "text": "# A\n"},
                    {"name": "deep", "kind": "dir", "entries": []}]},
                {"name": "src", "kind": "dir"},
                {"name": "latest", "kind": "symlink", "target": "README.txt"},
                {"name": "owned", "kind": "file", "uid": 7, "gid": 8, "mode": 384}
            ]}),
        )
        .unwrap();
    assert_eq!(n, 8);
    t
}

fn ino(t: &Tree, parent: u64, name: &str) -> u64 {
    t.lookup(parent, name).unwrap().ino
}

#[test]
fn a_description_is_served_without_asking_again() {
    let t = described();
    let readme = t.lookup(ROOT, "README.txt").unwrap();
    assert_eq!(
        (readme.kind, readme.size, readme.perm, readme.uid),
        (Kind::File, 6, 0o644, 1000)
    );
    assert_eq!(
        readme
            .mtime
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        1700000000
    );
    assert_eq!(t.read(readme.ino, 0, 100).unwrap(), b"hello\n");
    assert_eq!(t.read(readme.ino, 2, 2).unwrap(), b"ll");
    assert_eq!(t.read(readme.ino, 6, 10).unwrap(), b"");

    let disk = ino(&t, ROOT, "disk.img");
    assert_eq!(t.read(disk, 0, 6).unwrap(), [0xde, 0xad, 0xbe, 0xef, 0, 0]);
    assert_eq!(t.read(disk, 4094, 4).unwrap(), [0, 0, 0xab, 0xab]);
    assert_eq!(t.read(disk, 8191, 1).unwrap(), [0xab]);
    assert_eq!(t.read(disk, 8190, 4), Err(errno(libc::EIO)));
    assert_eq!(t.read(disk, 8704, 16).unwrap(), vec![0; 16]);

    // Inline subdirectories are described; one without entries waits for its own answer.
    let docs = ino(&t, ROOT, "docs");
    assert_eq!(t.dir_state(docs), Some(DirState::Described));
    assert_eq!(t.attr(docs).unwrap().nlink, 3);
    assert_eq!(t.read(ino(&t, docs, "a.md"), 0, 10).unwrap(), b"# A\n");
    let src = ino(&t, ROOT, "src");
    assert_eq!(t.dir_state(src), Some(DirState::Pending(0)));
    assert_eq!(t.lookup(src, "x"), Err(Stop::Describe(src)));
    assert_eq!(t.list(src), Err(Stop::Describe(src)));
    assert_eq!(t.path(ino(&t, docs, "deep")), "/docs/deep");
    assert_eq!(t.depth(ino(&t, docs, "deep")), 2);

    let latest = ino(&t, ROOT, "latest");
    assert_eq!(t.readlink(latest).unwrap(), "README.txt");
    assert_eq!(t.attr(latest).unwrap().perm, 0o777);
    let owned = t.lookup(ROOT, "owned").unwrap();
    assert_eq!(
        (owned.uid, owned.gid, owned.perm, owned.size),
        (7, 8, 0o600, 0)
    );
    assert_eq!(t.lookup(ROOT, "nope"), Err(errno(libc::ENOENT)));
    assert_eq!(
        t.list(ROOT)
            .unwrap()
            .iter()
            .map(|(_, _, n)| n.as_str())
            .collect::<Vec<_>>(),
        vec!["README.txt", "disk.img", "docs", "latest", "owned", "src"]
    );
}

#[test]
fn a_broken_answer_is_refused_whole_and_changes_nothing() {
    let bad = [
        json!({"entries": [{"name": "a", "kind": "file"}, {"name": "a", "kind": "file"}]}),
        json!({"entries": [{"name": "a/b", "kind": "file"}]}),
        json!({"entries": [{"name": "..", "kind": "dir"}]}),
        json!({"entries": [{"name": "x".repeat(256), "kind": "file"}]}),
        json!({"entries": [{"name": "a", "kind": "device"}]}),
        json!({"entries": [{"name": "a", "kind": "file", "text": "long", "size": 2}]}),
        json!({"entries": [{"name": "a", "kind": "file", "extents": [{"offset": 0, "text": "x"}]}]}),
        json!({"entries": [{"name": "a", "kind": "file", "text": "x", "hex": "00"}]}),
        json!({"entries": [{"name": "a", "kind": "file", "size": 2147483648u64}]}),
        json!({"entries": [{"name": "a", "kind": "file", "size": 10, "errors": [{"offset": 0, "length": 1, "error": "EWHAT"}]}]}),
        json!({"entries": [{"name": "a", "kind": "symlink", "target": ""}]}),
        json!({"entries": [{"name": "a", "kind": "file", "mode": 4096}]}),
        json!({"entries": [{"name": "ok", "kind": "file"}, {"name": "d", "kind": "dir", "entries": [{"name": "", "kind": "file"}]}]}),
        json!({"entries": "not a list"}),
        json!({}),
    ];
    for answer in bad {
        let mut t = Tree::new(0o755, 0, 0, DEFAULT_MAX_OVERLAY_BYTES);
        assert!(t.describe(ROOT, &answer).is_err(), "refused: {answer}");
        assert!(check_description(&answer).is_err());
        assert_eq!(t.node_count(), 1, "nothing committed from {answer}");
        assert_eq!(t.dir_state(ROOT), Some(DirState::Pending(0)));
    }
}

#[test]
fn the_entry_bounds_hold() {
    let many: Vec<_> = (0..=MAX_DIR_ENTRIES)
        .map(|i| json!({"name": format!("f{i}"), "kind": "file"}))
        .collect();
    let err = check_description(&json!({"entries": many})).unwrap_err();
    assert!(format!("{err}").contains("at most 4096 entries"), "{err}");
    let fits: Vec<_> = (0..MAX_DIR_ENTRIES)
        .map(|i| json!({"name": format!("f{i}"), "kind": "file"}))
        .collect();
    assert_eq!(
        check_description(&json!({"entries": fits})).unwrap(),
        MAX_DIR_ENTRIES
    );
    // Explicit content over the whole tree.
    let big = "x".repeat(MAX_DESCRIBED_BYTES / 2 + 1);
    let err = check_description(&json!({"entries": [
        {"name": "a", "kind": "file", "text": big.clone()},
        {"name": "b", "kind": "file", "text": big}
    ]}))
    .unwrap_err();
    assert!(
        format!("{err}").contains("text and hex are at most"),
        "{err}"
    );
}

/// A description nested past the bound — a depth bomb in one answer — is refused, and so is
/// one that would reach past it from a directory already deep in the tree.
#[test]
fn the_depth_bound_holds_inline_and_lazily() {
    let nest = |levels: usize| {
        let mut v = json!([{"name": "leaf", "kind": "file", "text": "x"}]);
        for _ in 0..levels {
            v = json!([{"name": "d", "kind": "dir", "entries": v}]);
        }
        json!({"entries": v})
    };
    // 63 nested directories put the leaf at depth 64: allowed. One more is refused.
    assert!(check_description(&nest(63)).is_ok());
    let err = check_description(&nest(64)).unwrap_err();
    assert!(format!("{err}").contains("64 directories deep"), "{err}");
    // serde_json stops parsing at 128 levels, but a static handler's answer is a value nobody
    // parsed: a deeper one is refused by the walk's own count.
    assert!(check_description(&nest(120)).is_err());

    // Lazily: one level per answer, down to the bound.
    let mut t = Tree::new(0o755, 0, 0, DEFAULT_MAX_OVERLAY_BYTES);
    let mut dir = ROOT;
    for depth in 0..MAX_TREE_DEPTH {
        t.describe(dir, &json!({"entries": [{"name": "d", "kind": "dir"}]}))
            .unwrap_or_else(|e| panic!("depth {depth}: {e}"));
        dir = ino(&t, dir, "d");
    }
    assert_eq!(t.depth(dir), MAX_TREE_DEPTH);
    assert!(t
        .describe(dir, &json!({"entries": [{"name": "d", "kind": "dir"}]}))
        .is_err());
    // mkdir at the bound is refused too.
    t.description_failed(dir);
    let parent = t.parent(dir).unwrap();
    let below = t.mkdir(parent, "e", 0o755, 0, 0).unwrap();
    assert_eq!(
        t.mkdir(below.ino, "f", 0o755, 0, 0),
        Err(errno(libc::ENAMETOOLONG))
    );
}

#[test]
fn descriptions_fail_three_times_or_are_refused_once() {
    let mut t = described();
    let src = ino(&t, ROOT, "src");
    assert!(!t.description_failed(src));
    assert!(!t.description_failed(src));
    assert!(t.description_failed(src));
    assert_eq!(t.dir_state(src), Some(DirState::Failed));
    assert_eq!(t.lookup(src, "x"), Err(errno(libc::EIO)));
    let docs_deep = ino(&t, ino(&t, ROOT, "docs"), "deep");
    assert_eq!(t.list(docs_deep).unwrap(), vec![]);

    let mut t = described();
    let src = ino(&t, ROOT, "src");
    t.description_refused(src, libc::EACCES);
    assert_eq!(t.list(src), Err(errno(libc::EACCES)));
    assert_eq!(t.lookup(src, "x"), Err(errno(libc::EACCES)));
}

#[test]
fn writes_land_in_the_overlay_over_the_description() {
    let mut t = described();
    let disk = ino(&t, ROOT, "disk.img");
    // A write across a page boundary, over described bytes.
    assert_eq!(t.write(disk, 4094, b"WXYZ").unwrap(), 4);
    assert_eq!(t.overlay_bytes(), 2 * PAGE);
    assert_eq!(
        t.read(disk, 4092, 8).unwrap(),
        [0, 0, b'W', b'X', b'Y', b'Z', 0xab, 0xab]
    );
    assert_eq!(t.read(disk, 0, 4).unwrap(), [0xde, 0xad, 0xbe, 0xef]);
    // Overwriting a failing region repairs it.
    assert_eq!(t.read(disk, 8192, 1), Err(errno(libc::EIO)));
    t.write(disk, 8192, &[1; 512]).unwrap();
    assert_eq!(t.read(disk, 8190, 4).unwrap(), [0xab, 0xab, 1, 1]);
    // Past the end: the file grows, the gap reads as zeroes.
    t.write(disk, 20000, b"end").unwrap();
    assert_eq!(t.attr(disk).unwrap().size, 20003);
    assert_eq!(t.read(disk, 19998, 5).unwrap(), [0, 0, b'e', b'n', b'd']);
    assert_eq!(t.read(disk, 12288, 4).unwrap(), [0; 4]);

    // Truncate: shrinking hides described bytes, growing again shows zeroes.
    let readme = ino(&t, ROOT, "README.txt");
    t.truncate(readme, 3).unwrap();
    assert_eq!(t.read(readme, 0, 10).unwrap(), b"hel");
    t.truncate(readme, 6).unwrap();
    assert_eq!(t.read(readme, 0, 10).unwrap(), b"hel\0\0\0");
    // Inside a written page too.
    t.write(readme, 0, b"HELLO!").unwrap();
    t.truncate(readme, 2).unwrap();
    t.truncate(readme, 4).unwrap();
    assert_eq!(t.read(readme, 0, 10).unwrap(), b"HE\0\0");
    assert_eq!(
        t.truncate(readme, MAX_FILE_SIZE + 1),
        Err(errno(libc::EFBIG))
    );
    assert_eq!(
        t.check_write(readme, MAX_FILE_SIZE - 1, 2),
        Err(errno(libc::EFBIG))
    );
    // Shrinking to zero frees its pages.
    let before = t.overlay_bytes();
    t.truncate(readme, 0).unwrap();
    assert_eq!(t.overlay_bytes(), before - PAGE);
}

#[test]
fn the_overlay_cap_refuses_and_leaves_everything_as_it_was() {
    let mut t = Tree::new(0o755, 0, 0, 2 * PAGE);
    t.describe(
        ROOT,
        &json!({"entries": [{"name": "f", "kind": "file", "text": "base"}]}),
    )
    .unwrap();
    let f = ino(&t, ROOT, "f");
    t.write(f, 0, &[7; 8192]).unwrap();
    assert_eq!(t.overlay_bytes(), 2 * PAGE);
    // Rewriting pages already in the overlay costs nothing.
    t.write(f, 100, b"again").unwrap();
    assert_eq!(t.write(f, 8192, b"x"), Err(errno(libc::ENOSPC)));
    assert_eq!(t.attr(f).unwrap().size, 8192);
    assert_eq!(t.read(f, 8190, 4).unwrap(), [7, 7]);
    assert_eq!(t.overlay_bytes(), 2 * PAGE);
    assert_eq!(
        t.symlink(ROOT, "l", "target", 0, 0),
        Err(errno(libc::ENOSPC))
    );
    // Removing the file frees its pages.
    t.unlink(ROOT, "f").unwrap();
    assert_eq!(t.overlay_bytes(), 0);
    let l = t.symlink(ROOT, "l", "target", 0, 0).unwrap();
    assert_eq!(t.readlink(l.ino).unwrap(), "target");
    assert_eq!(t.overlay_bytes(), 6);
}

#[test]
fn creates_removals_and_renames_follow_posix() {
    let mut t = described();
    let docs = ino(&t, ROOT, "docs");
    let a = t.create(docs, "new.txt", 0o640, 5, 6).unwrap();
    assert_eq!((a.perm, a.uid, a.gid, a.size), (0o640, 5, 6, 0));
    assert_eq!(
        t.create(docs, "new.txt", 0o640, 5, 6),
        Err(errno(libc::EEXIST))
    );
    assert_eq!(
        t.create(docs, &"n".repeat(256), 0o640, 0, 0),
        Err(errno(libc::ENAMETOOLONG))
    );
    // Creating in a directory nobody described needs its description first.
    let src = ino(&t, ROOT, "src");
    assert_eq!(t.check_new_entry(src, "x"), Err(Stop::Describe(src)));

    // rmdir: not empty, empty, not a directory.
    assert_eq!(t.rmdir(ROOT, "docs"), Err(errno(libc::ENOTEMPTY)));
    assert_eq!(t.rmdir(docs, "deep"), Ok(()));
    assert_eq!(t.rmdir(ROOT, "README.txt"), Err(errno(libc::ENOTDIR)));
    assert_eq!(t.check_rmdir(ROOT, "src"), Err(Stop::Describe(src)));
    assert_eq!(t.unlink(ROOT, "docs"), Err(errno(libc::EISDIR)));

    // rename: within, across, replacing, refusing.
    t.rename(docs, "new.txt", ROOT, "moved.txt", false).unwrap();
    assert_eq!(t.lookup(docs, "new.txt"), Err(errno(libc::ENOENT)));
    assert_eq!(t.path(ino(&t, ROOT, "moved.txt")), "/moved.txt");
    assert_eq!(
        t.rename(ROOT, "moved.txt", ROOT, "README.txt", true),
        Err(errno(libc::EEXIST))
    );
    t.rename(ROOT, "moved.txt", ROOT, "README.txt", false)
        .unwrap();
    assert_eq!(t.attr(ino(&t, ROOT, "README.txt")).unwrap().size, 0);
    assert_eq!(
        t.rename(ROOT, "docs", docs, "inside", false),
        Err(errno(libc::EINVAL))
    );
    assert_eq!(
        t.rename(ROOT, "README.txt", ROOT, "docs", false),
        Err(errno(libc::EISDIR))
    );
    t.mkdir(ROOT, "empty", 0o755, 0, 0).unwrap();
    assert_eq!(
        t.rename(ROOT, "empty", ROOT, "README.txt", false),
        Err(errno(libc::ENOTDIR))
    );
    t.rename(ROOT, "empty", ROOT, "docs2", false).unwrap();
    t.rename(ROOT, "docs2", docs, "sub", false).unwrap();
    assert_eq!(t.path(ino(&t, docs, "sub")), "/docs/sub");
    assert_eq!(t.attr(docs).unwrap().nlink, 3);
    assert_eq!(t.rename(ROOT, "docs", ROOT, "docs", false), Ok(()));

    // An unlinked file stays readable while it is open.
    let f = t.create(ROOT, "open.txt", 0o644, 0, 0).unwrap().ino;
    t.write(f, 0, b"still here").unwrap();
    t.opened(f);
    t.unlink(ROOT, "open.txt").unwrap();
    assert_eq!(t.lookup(ROOT, "open.txt"), Err(errno(libc::ENOENT)));
    assert_eq!(t.read(f, 0, 20).unwrap(), b"still here");
    assert_eq!(t.attr(f).unwrap().nlink, 0, "no name is left");
    let before = t.overlay_bytes();
    t.released(f);
    assert_eq!(t.overlay_bytes(), before - PAGE);
    assert!(t.attr(f).is_none());

    // FIFOs, sockets and device nodes are names with a type; the kernel serves their I/O.
    let fifo = t.mknod(ROOT, "pipe", Kind::Fifo, 0o600, 0, 0, 0).unwrap();
    assert_eq!((fifo.kind, fifo.size, fifo.perm), (Kind::Fifo, 0, 0o600));
    assert_eq!(t.read(fifo.ino, 0, 1), Err(errno(libc::EINVAL)));
    let dev = t
        .mknod(ROOT, "null", Kind::CharDevice, 0o666, 0x0103, 0, 0)
        .unwrap();
    assert_eq!(dev.rdev, 0x0103);
    assert_eq!(
        t.mknod(ROOT, "x", Kind::File, 0o644, 0, 0, 0),
        Err(errno(libc::EINVAL))
    );
    assert_eq!(
        t.mknod(ROOT, "pipe", Kind::Socket, 0o644, 0, 0, 0),
        Err(errno(libc::EEXIST))
    );
    t.unlink(ROOT, "pipe").unwrap();

    // setattr changes only what it names.
    let r = ino(&t, ROOT, "README.txt");
    let a = t
        .setattr(
            r,
            &Changes {
                perm: Some(0o600),
                uid: Some(42),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!((a.perm, a.uid, a.gid), (0o600, 42, 6));
}

#[test]
fn errno_names_round_trip() {
    for name in ERRNO_NAMES.split([',', ' ']).filter(|n| n.starts_with('E')) {
        let code = errno_named(name).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(errno_name(code), name);
    }
    assert_eq!(errno_named("eacces"), Some(libc::EACCES));
    assert_eq!(errno_named("EWHAT"), None);
}

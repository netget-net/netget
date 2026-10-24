//! NetGet's UnixFS builder against Kubo 0.43.1's own importer (`NETGET_KUBO`): for every file
//! and directory described here, the same bytes written to disk and added with `ipfs add
//! --only-hash` and the matching flags must give the root CID NetGet computes. No daemon and
//! no network: Kubo only chunks and hashes.
//!
//! Also pure checks of the bounds: block count, depth, HAMT threshold, and the walker's
//! limits against a depth bomb.
pub use crate::helpers::ipfs_fixtures::{noise, tree, write_tree};
use crate::helpers::kubo::Kubo;
use netget::server::libp2p::ipfs::{self, Cid, Link, PbNode, UnixFs};
use netget::server::libp2p::unixfs::{self, Walk};
use serde_json::{json, Value};

/// Kubo's flags and NetGet's description fields for each import profile tested.
pub fn profiles() -> Vec<(Value, Vec<&'static str>)> {
    vec![
        (json!({}), vec![]),
        (json!({"cid_version": 1}), vec!["--cid-version=1"]),
        (json!({"raw_leaves": true}), vec!["--raw-leaves"]),
        (
            json!({"cid_version": 1, "raw_leaves": false}),
            vec!["--cid-version=1", "--raw-leaves=false"],
        ),
        (
            json!({"cid_version": 1, "chunk_size": 1048576, "max_links": 1024}),
            vec![
                "--cid-version=1",
                "--chunker=size-1048576",
                "--max-file-links=1024",
            ],
        ),
        (
            json!({"chunk_size": 256, "max_links": 3}),
            vec!["--chunker=size-256", "--max-file-links=3"],
        ),
        (
            json!({"cid_version": 1, "chunk_size": 256, "max_links": 3}),
            vec![
                "--cid-version=1",
                "--chunker=size-256",
                "--max-file-links=3",
            ],
        ),
    ]
}

fn with(profile: &Value, mut desc: Value) -> Value {
    for (k, v) in profile.as_object().unwrap() {
        desc[k] = v.clone();
    }
    desc
}

pub async fn kubo_hash(kubo: &Kubo, flags: &[&str], path: &str, recursive: bool) -> String {
    let mut args = vec!["add", "-Q", "-n"];
    if recursive {
        args.push("-r");
    }
    args.extend(flags);
    args.push(path);
    String::from_utf8(kubo.ok(&args).await)
        .unwrap()
        .trim()
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unixfs_files_agree_with_kubo() {
    let kubo = Kubo::offline().await;
    let sizes = [
        0usize, 1, 255, 256, 257, 6912, 7168, 262_143, 262_144, 262_145, 600_000, 2_200_000,
    ];
    let mut checked = 0;
    for (size_i, &size) in sizes.iter().enumerate() {
        let bytes = noise(size_i as u64 + 1, size);
        let path = kubo.file(&format!("f{size}.bin"), &bytes);
        for (profile, flags) in profiles() {
            // 256-byte chunks on the two largest files make tens of thousands of blocks;
            // the small ones already reach depth 5 and the one-child last node.
            if profile["chunk_size"] == 256 && size > 262_145 {
                continue;
            }
            let ours = unixfs::add(&with(&profile, json!({"hex": hex::encode(&bytes)})))
                .unwrap_or_else(|e| panic!("{size} bytes {profile}: {e:#}"));
            let theirs = kubo_hash(&kubo, &flags, &path, false).await;
            assert_eq!(
                ours.root.to_string(),
                theirs,
                "{size} bytes with {flags:?}: NetGet built {} blocks, depth {}",
                ours.blocks.len(),
                ours.depth
            );
            checked += 1;
        }
    }
    // Extents and fill bytes describe the same file as its bytes do.
    let mut sparse = vec![0u8; 1_000_000];
    sparse[..4].copy_from_slice(b"head");
    sparse[500_000..501_000].fill(7);
    sparse[999_990..].copy_from_slice(b"0123456789");
    let path = kubo.file("sparse.bin", &sparse);
    for (profile, flags) in profiles().into_iter().take(5) {
        let desc = with(
            &profile,
            json!({"size": 1_000_000, "extents": [
                {"offset": 0, "text": "head"},
                {"offset": 500_000, "length": 1000, "fill": 7},
                {"offset": 999_990, "text": "0123456789"},
            ]}),
        );
        let ours = unixfs::add(&desc).unwrap();
        assert_eq!(
            ours.root.to_string(),
            kubo_hash(&kubo, &flags, &path, false).await,
            "sparse file with {flags:?}"
        );
        checked += 1;
    }
    println!("{checked} file roots agree with Kubo's ipfs add --only-hash");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unixfs_directories_agree_with_kubo() {
    let kubo = Kubo::offline().await;
    let (desc, disk) = tree();
    let root = kubo.path().join("site");
    write_tree(&root, &disk);
    let root = root.to_string_lossy().to_string();
    for (profile, flags) in profiles().into_iter().take(5) {
        let ours = unixfs::add(&with(&profile, desc.clone())).unwrap();
        assert_eq!(ours.kind, "directory");
        assert_eq!(
            ours.root.to_string(),
            kubo_hash(&kubo, &flags, &root, true).await,
            "directory with {flags:?}"
        );
    }
    // A single symlink, and an empty directory, on their own.
    let link = kubo.path().join("lonely-link");
    std::os::unix::fs::symlink("somewhere/else", &link).unwrap();
    let ours = unixfs::add(&json!({"kind": "symlink", "target": "somewhere/else"})).unwrap();
    assert_eq!(
        ours.root.to_string(),
        kubo_hash(&kubo, &[], &link.to_string_lossy(), false).await
    );
    let empty = kubo.path().join("nothing-here");
    std::fs::create_dir(&empty).unwrap();
    let ours = unixfs::add(&json!({"kind": "dir"})).unwrap();
    assert_eq!(
        ours.root.to_string(),
        kubo_hash(&kubo, &[], &empty.to_string_lossy(), true).await
    );
    assert_eq!(
        ours.root.to_string(),
        "QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directory_kubo_would_shard_is_refused() {
    let kubo = Kubo::offline().await;
    // 900 entries with 200-byte names: under the 256 KiB threshold by both measures, so
    // Kubo builds a basic directory and NetGet's agrees with it.
    let names = |n: usize| -> Vec<String> {
        (0..n)
            .map(|i| format!("{i:05}{}", "n".repeat(195)))
            .collect()
    };
    for (n, agree) in [(900, true), (1200, false)] {
        let dir = kubo.path().join(format!("wide{n}"));
        std::fs::create_dir(&dir).unwrap();
        let mut entries = Vec::new();
        for name in names(n) {
            std::fs::write(dir.join(&name), name.as_bytes()).unwrap();
            entries.push(json!({"name": name, "text": name}));
        }
        let theirs = kubo_hash(&kubo, &[], &dir.to_string_lossy(), true).await;
        let ours = unixfs::add(&json!({"entries": entries}));
        if agree {
            assert_eq!(ours.unwrap().root.to_string(), theirs);
        } else {
            let e = format!("{:#}", ours.err().expect("refused"));
            assert!(e.contains("HAMT"), "{e}");
            // Kubo did shard it: its root is a hamt-shard node, not a basic directory.
            kubo.ok(&["add", "-Q", "-r", &dir.to_string_lossy()]).await;
            let block = kubo.ok(&["block", "get", &theirs]).await;
            let cid = Cid::parse(&theirs).unwrap();
            let d = ipfs::describe(&cid, &block).unwrap();
            assert_eq!(d.unixfs_type.as_deref(), Some("hamt-shard"));
        }
    }
}

#[test]
fn the_builder_is_bounded() {
    // Block count: 65 537 chunks of 256 bytes.
    let e = unixfs::add(&json!({"size": 256 * 65_537, "chunk_size": 256,
        "extents": [{"offset": 0, "length": 256 * 65_537, "fill": 1}]}))
    .err()
    .unwrap();
    assert!(format!("{e:#}").contains("blocks"), "{e:#}");
    // Size.
    let e = unixfs::add(&json!({"size": unixfs::MAX_ADD_BYTES + 1, "extents": []}))
        .err()
        .unwrap();
    assert!(format!("{e:#}").contains("at most"), "{e:#}");
    // Directory depth: MAX_DIR_DEPTH + 1 nested directories.
    let mut d = json!({"name": "d", "kind": "dir", "entries": []});
    for _ in 0..=unixfs::MAX_DIR_DEPTH {
        d = json!({"name": "d", "kind": "dir", "entries": [d]});
    }
    let e = unixfs::add(&json!({"entries": [d]})).err().unwrap();
    assert!(format!("{e:#}").contains("deep"), "{e:#}");
    let mut ok = json!({"name": "d", "kind": "dir", "entries": []});
    for _ in 0..unixfs::MAX_DIR_DEPTH - 1 {
        ok = json!({"name": "d", "kind": "dir", "entries": [ok]});
    }
    ok["name"] = json!("d");
    assert!(unixfs::add(&json!({"entries": [ok]})).is_ok());
    // Depth of a file DAG: two links per node and 256-byte chunks reach depth 15 within the
    // block bound, which is under MAX_DAG_DEPTH; the bound is checked as the tree grows.
    let b = unixfs::add(
        &json!({"size": 256 * 30_000, "chunk_size": 256, "max_links": 2,
        "extents": [{"offset": 0, "length": 256 * 30_000, "fill": 3}]}),
    )
    .unwrap();
    assert_eq!(b.depth, 15);
    // The same file 20 directories down is a DAG 36 deep: past MAX_DAG_DEPTH, refused.
    let mut nested = json!({"name": "f", "size": 256 * 30_000, "extents": []});
    for _ in 0..20 {
        nested = json!({"name": "d", "kind": "dir", "entries": [nested]});
    }
    let deep = json!({"entries": [nested], "chunk_size": 256, "max_links": 2});
    let e = unixfs::add(&deep).err().unwrap();
    assert!(
        format!("{e:#}").contains(&format!("deeper than {}", unixfs::MAX_DAG_DEPTH)),
        "{e:#}"
    );
    // Names and duplicates.
    for bad in [
        json!([{"name": "a/b", "text": ""}]),
        json!([{"name": "..", "text": ""}]),
        json!([{"name": "x", "text": ""}, {"name": "x", "text": ""}]),
    ] {
        assert!(unixfs::add(&json!({"entries": bad})).is_err());
    }
    // Layout options out of range.
    for bad in [
        json!({"cid_version": 2}),
        json!({"chunk_size": 255}),
        json!({"chunk_size": unixfs::MAX_CHUNK_SIZE + 1}),
        json!({"max_links": 1}),
    ] {
        let mut d = bad.clone();
        d["text"] = json!("x");
        assert!(unixfs::add(&d).is_err(), "{bad}");
    }
}

/// A chain of dag-pb file nodes, each linking to the next: a depth bomb for a walker.
pub fn chain(depth: usize) -> (Cid, Vec<(Cid, Vec<u8>)>) {
    let leaf = b"bottom".to_vec();
    let mut cid = Cid::v1(ipfs::RAW, &leaf);
    let mut blocks = vec![(cid, leaf)];
    for _ in 0..depth {
        let node = ipfs::encode_pb_node(&PbNode {
            links: vec![Link {
                cid,
                name: String::new(),
                size: 6,
            }],
            data: Some(ipfs::encode_unixfs(&UnixFs {
                kind: "file".into(),
                data: Vec::new(),
                file_size: Some(6),
                block_sizes: vec![6],
            })),
        });
        cid = Cid::v1(ipfs::DAG_PB, &node);
        blocks.push((cid, node));
    }
    (cid, blocks)
}

/// Run a walk against a set of blocks: what the walk ended with.
pub fn walk_all(
    root: Cid,
    blocks: &[(Cid, Vec<u8>)],
    keep: usize,
) -> anyhow::Result<unixfs::Walked> {
    let mut w = Walk::new(root, keep);
    loop {
        if let Some(done) = w.step()? {
            return Ok(done.clone());
        }
        let wants = w.wants();
        anyhow::ensure!(!wants.is_empty() || w.ready(), "stuck");
        for c in wants {
            let (_, data) = blocks
                .iter()
                .find(|(b, _)| b.same_block(&c))
                .ok_or_else(|| anyhow::anyhow!("{c} missing"))?;
            w.give(&c, data.clone())?;
        }
    }
}

#[test]
fn the_walker_reads_back_what_the_builder_built() {
    let (desc, _) = tree();
    for (profile, _) in profiles().into_iter().take(5) {
        let built = unixfs::add(&with(&profile, desc.clone())).unwrap();
        let mut store = unixfs::Store::default();
        let blocks: Vec<(Cid, Vec<u8>)> =
            built.blocks.iter().map(|(c, s)| (*c, s.bytes())).collect();
        store.insert(built).unwrap();
        let root = store.roots()[0].root;
        let listing = walk_all(root, &blocks, 1024).unwrap();
        assert_eq!(listing.kind, "directory");
        let names: Vec<_> = listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "a.txt",
                "big.bin",
                "empty.txt",
                "emptydir",
                "link",
                "sub",
                "ünïcode name.txt"
            ]
        );
        let big = listing
            .entries
            .iter()
            .find(|e| e.name == "big.bin")
            .unwrap();
        assert_eq!(
            (big.kind.as_deref(), big.size),
            (Some("file"), Some(700_000))
        );
        let link = listing.entries.iter().find(|e| e.name == "link").unwrap();
        assert_eq!(link.kind.as_deref(), Some("symlink"));
        let file = walk_all(big.cid, &blocks, 100).unwrap();
        assert_eq!(file.size, 700_000);
        assert_eq!(file.data, noise(42, 100));
        assert_eq!(file.sha256, ipfs::sha256(&noise(42, 700_000)));
        // Every block the store serves hashes to its CID.
        for (c, b) in &blocks {
            assert_eq!(store.get(c).as_deref(), Some(b.as_slice()));
        }
    }
}

#[test]
fn the_walker_is_bounded() {
    // Depth: a chain one past MAX_DAG_DEPTH is refused; one at it is read.
    let (root, blocks) = chain(unixfs::MAX_DAG_DEPTH + 1);
    let e = walk_all(root, &blocks, 64).unwrap_err();
    assert!(format!("{e:#}").contains("deeper"), "{e:#}");
    let (root, blocks) = chain(unixfs::MAX_DAG_DEPTH);
    assert_eq!(walk_all(root, &blocks, 64).unwrap().data, b"bottom");
    // A depth bomb thousands deep costs no stack: it is refused at the bound.
    let (root, blocks) = chain(10_000);
    assert!(walk_all(root, &blocks, 64).is_err());
    // Blocks: 3 links to a node of 3000 links to one leaf name 9004 blocks in two small nodes,
    // past MAX_WALK_BLOCKS (8192): the walk stops at its bound. (Small enough that a walk
    // without the bound finishes, so removing it fails this rather than hanging it.)
    let leaf = Cid::v1(ipfs::RAW, b"x");
    let fan = |child: Cid, n: usize| {
        ipfs::encode_pb_node(&PbNode {
            links: vec![
                Link {
                    cid: child,
                    name: String::new(),
                    size: 1
                };
                n
            ],
            data: Some(ipfs::encode_unixfs(&UnixFs {
                kind: "file".into(),
                data: Vec::new(),
                file_size: Some(n as u64 * 3000),
                block_sizes: vec![],
            })),
        })
    };
    let wide = fan(leaf, 3000);
    let wide_cid = Cid::v1(ipfs::DAG_PB, &wide);
    let top = fan(wide_cid, 3);
    let root = Cid::v1(ipfs::DAG_PB, &top);
    let e = walk_all(
        root,
        &[(root, top), (wide_cid, wide), (leaf, b"x".to_vec())],
        64,
    )
    .unwrap_err();
    assert!(
        format!("{e:#}").contains(&format!("more than {} blocks", unixfs::MAX_WALK_BLOCKS)),
        "{e:#}"
    );
    // A block that does not hash to what was asked is refused.
    let mut w = Walk::new(leaf, 64);
    let asked = w.wants();
    assert_eq!(asked, vec![leaf]);
    assert!(w.give(&leaf, b"y".to_vec()).is_err());
    // A root that lies about its file size.
    let liar = ipfs::encode_pb_node(&PbNode {
        links: vec![Link {
            cid: leaf,
            name: String::new(),
            size: 1,
        }],
        data: Some(ipfs::encode_unixfs(&UnixFs {
            kind: "file".into(),
            data: Vec::new(),
            file_size: Some(2),
            block_sizes: vec![2],
        })),
    });
    let root = Cid::v1(ipfs::DAG_PB, &liar);
    let e = walk_all(root, &[(root, liar), (leaf, b"x".to_vec())], 64).unwrap_err();
    assert!(format!("{e:#}").contains("says 2 bytes"), "{e:#}");
}

/// Helia's flags for a profile: `--cid-version`, `--raw-leaves`, `--chunk`, `--max-links`.
pub fn helia_flags(profile: &Value) -> Vec<String> {
    let mut f = Vec::new();
    if let Some(v) = profile["cid_version"].as_u64() {
        f.push(format!("--cid-version={v}"));
    }
    if let Some(r) = profile["raw_leaves"].as_bool() {
        f.push(format!("--raw-leaves={r}"));
    }
    if let Some(c) = profile["chunk_size"].as_u64() {
        f.push(format!("--chunk={c}"));
    }
    if let Some(m) = profile["max_links"].as_u64() {
        f.push(format!("--max-links={m}"));
    }
    f
}

pub async fn helia_cid(path: &str, profile: &Value) -> String {
    let flags = helia_flags(profile);
    let mut args = vec!["cid", path];
    args.extend(flags.iter().map(String::as_str));
    let (lines, text) = crate::helpers::helia::run(&args).await;
    crate::helpers::helia::step(&lines, "cid", &text)["cid"]
        .as_str()
        .unwrap()
        .to_string()
}

/// The same files and trees through a second, independent importer: Helia's
/// ipfs-unixfs-importer (JavaScript) must reach the root CID NetGet and Kubo reach.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn helia_importer_agrees_with_netget_and_kubo() {
    let kubo = Kubo::offline().await;
    let mut checked = 0;
    for (i, size) in [0usize, 1, 7168, 262_145, 600_000].into_iter().enumerate() {
        let bytes = noise(100 + i as u64, size);
        let path = kubo.file(&format!("h{size}.bin"), &bytes);
        for (profile, flags) in profiles() {
            if profile["chunk_size"] == 256 && size > 262_145 {
                continue;
            }
            let ours = unixfs::add(&with(&profile, json!({"hex": hex::encode(&bytes)})))
                .unwrap()
                .root
                .to_string();
            let helia = helia_cid(&path, &profile).await;
            assert_eq!(ours, helia, "{size} bytes, {profile}: NetGet vs Helia");
            assert_eq!(ours, kubo_hash(&kubo, &flags, &path, false).await);
            checked += 1;
        }
    }
    // The tree without its symlink (the importer takes files and directories only).
    let (mut desc, disk) = tree();
    desc["entries"]
        .as_array_mut()
        .unwrap()
        .retain(|e| e["kind"] != "symlink");
    let disk: Vec<_> = disk.into_iter().filter(|(p, _, _)| p != "link").collect();
    let root = kubo.path().join("site");
    write_tree(&root, &disk);
    let root = root.to_string_lossy().to_string();
    for (profile, flags) in profiles().into_iter().take(5) {
        let ours = unixfs::add(&with(&profile, desc.clone()))
            .unwrap()
            .root
            .to_string();
        assert_eq!(ours, helia_cid(&root, &profile).await, "tree, {profile}");
        assert_eq!(ours, kubo_hash(&kubo, &flags, &root, true).await);
        checked += 1;
    }
    println!(
        "{checked} roots agree three ways: NetGet, Kubo 0.43.1, Helia's ipfs-unixfs-importer 17.1.1"
    );
}

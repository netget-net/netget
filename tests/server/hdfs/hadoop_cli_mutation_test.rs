//! append, truncate and concat through Apache Hadoop 3.5.0's own `hdfs dfs` (Java's
//! DFSClient: its DataStreamer reopening a partial last block, its NameNode calls, `-truncate
//! -w` polling for block recovery). Every result is read back with `-cat` and `-checksum`,
//! the checksum compared with one computed here; the policy in `support.rs` plays the model.
use super::support::{self, hdfs_dfs, lines, md5md5crc32c, policy, start, Started, POLICY};
use std::collections::BTreeMap;

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "netget-hdfs-{name}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Write `data` to a local file in `dir` and return its path.
fn local(dir: &std::path::Path, name: &str, data: &[u8]) -> String {
    let p = dir.join(name);
    std::fs::write(&p, data).unwrap();
    p.to_string_lossy().into_owned()
}

fn print_methods(what: &str, server: &Started) -> BTreeMap<String, u64> {
    let methods = server.methods();
    println!("{what}: NameNode methods {methods:?}");
    println!("{what}: DataNode ops {:?}", server.ops());
    methods
}

/// `hdfs dfs -cat` as bytes are compared: the stdout of a text file.
async fn cat(server: &Started, path: &str) -> String {
    let r = hdfs_dfs(server, "alice", &["-cat", path]).await;
    r.expect_ok(&format!("hdfs dfs -cat {path}"), server);
    r.stdout.clone()
}

/// `-checksum` must be the MD5-of-MD5-of-CRC32C of `content` in 64 KiB blocks, computed here.
async fn checksum_is(server: &Started, path: &str, content: &[u8]) {
    let r = hdfs_dfs(server, "alice", &["-checksum", path]).await;
    r.expect_ok(&format!("hdfs dfs -checksum {path}"), server);
    let expected = hex::encode(md5md5crc32c(content, 65536));
    assert!(
        r.stdout.contains(&expected),
        "{path}: checksum {expected} expected: {}",
        r.stdout
    );
}

fn text(b: &[u8]) -> String {
    String::from_utf8(b.to_vec()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hadoop_cli_appends() {
    let server = start(policy(POLICY), None).await;
    let dir = scratch("append");
    // 70000 bytes in 64 KiB blocks: block 1 holds 4464 bytes, its last chunk 368 of 512.
    let first = lines(70000, "first");
    let more = lines(130000, "more");
    hdfs_dfs(
        &server,
        "alice",
        &[
            "-D",
            "dfs.blocksize=65536",
            "-put",
            &local(&dir, "first", &first),
            "/user/alice/grow.txt",
        ],
    )
    .await
    .expect_ok("hdfs dfs -put", &server);

    // The partial chunk is continued in a packet of its own, block 1 filled, two blocks added.
    hdfs_dfs(
        &server,
        "alice",
        &[
            "-appendToFile",
            &local(&dir, "more", &more),
            "/user/alice/grow.txt",
        ],
    )
    .await
    .expect_ok("hdfs dfs -appendToFile", &server);
    let all = [first.as_slice(), more.as_slice()].concat();
    assert_eq!(cat(&server, "/user/alice/grow.txt").await, text(&all));
    let stat = hdfs_dfs(
        &server,
        "alice",
        &["-stat", "%b %o %u", "/user/alice/grow.txt"],
    )
    .await;
    stat.expect_ok("hdfs dfs -stat", &server);
    assert_eq!(stat.stdout.trim(), "200000 65536 alice");
    checksum_is(&server, "/user/alice/grow.txt", &all).await;

    // A file whose last block is full: no block to reopen, the append starts a new one. Written
    // at replication 2 so that an append with the replace-datanode policy ALWAYS asks for an
    // additional DataNode (getAdditionalDatanode) — there is none, and with best effort the
    // client goes on with the one it has.
    let full = lines(65536, "full");
    hdfs_dfs(
        &server,
        "alice",
        &[
            "-D",
            "dfs.blocksize=65536",
            "-D",
            "dfs.replication=2",
            "-put",
            &local(&dir, "full", &full),
            "/tmp/full.txt",
        ],
    )
    .await
    .expect_ok("hdfs dfs -put of a whole block", &server);
    let tail1 = lines(1000, "tail1");
    hdfs_dfs(
        &server,
        "alice",
        &[
            "-appendToFile",
            &local(&dir, "tail1", &tail1),
            "/tmp/full.txt",
        ],
    )
    .await
    .expect_ok("hdfs dfs -appendToFile after a full block", &server);
    let tail2 = lines(3000, "tail2");
    hdfs_dfs(
        &server,
        "alice",
        &[
            "-D",
            "dfs.client.block.write.replace-datanode-on-failure.enable=true",
            "-D",
            "dfs.client.block.write.replace-datanode-on-failure.policy=ALWAYS",
            "-D",
            "dfs.client.block.write.replace-datanode-on-failure.best-effort=true",
            "-appendToFile",
            &local(&dir, "tail2", &tail2),
            "/tmp/full.txt",
        ],
    )
    .await
    .expect_ok(
        "hdfs dfs -appendToFile asking for an additional DataNode",
        &server,
    );
    let full_all = [full.as_slice(), tail1.as_slice(), tail2.as_slice()].concat();
    assert_eq!(cat(&server, "/tmp/full.txt").await, text(&full_all));
    checksum_is(&server, "/tmp/full.txt", &full_all).await;

    // -appendToFile -n (NEW_BLOCK) after a partial block would leave a short block mid-file.
    let n = hdfs_dfs(
        &server,
        "alice",
        &[
            "-appendToFile",
            "-n",
            &local(&dir, "n", b"x"),
            "/user/alice/grow.txt",
        ],
    )
    .await;
    n.expect_failure("hdfs dfs -appendToFile -n", &server);
    assert!(n.stderr.contains("variable-length block"), "{}", n.stderr);
    // The model refuses an append outside the tree it allows, and content it will not keep.
    let outside = hdfs_dfs(
        &server,
        "bob",
        &["-appendToFile", &local(&dir, "o", b"x"), "/data/events.csv"],
    )
    .await;
    outside.expect_failure("an append to /data", &server);
    assert!(
        outside.stderr.contains("Permission denied by policy"),
        "{}",
        outside.stderr
    );
    let bad = hdfs_dfs(
        &server,
        "alice",
        &[
            "-appendToFile",
            &local(&dir, "bad", b"this is forbidden content\n"),
            "/user/alice/grow.txt",
        ],
    )
    .await;
    bad.expect_failure("an append of refused content", &server);
    assert!(
        bad.stderr.contains("the model refuses this content"),
        "{}",
        bad.stderr
    );
    assert_eq!(
        cat(&server, "/user/alice/grow.txt").await,
        text(&all),
        "the refused bytes were not kept"
    );

    // What the model saw.
    let appends = support::events(&server.state, server.id, "hdfs_append").await;
    assert_eq!(appends[0]["path"], "/user/alice/grow.txt");
    assert_eq!(appends[0]["length"], 70000);
    assert_eq!(appends[0]["last_block_partial"], true);
    let writes = support::events(&server.state, server.id, "hdfs_write").await;
    let appended = writes
        .iter()
        .find(|w| w["path"] == "/user/alice/grow.txt" && w["append"] == true)
        .expect("the append's content was decided");
    assert_eq!(appended["offset"], 70000);
    assert_eq!(appended["length"], 130000);
    assert_eq!(appended["blocks"], 3, "the reopened block and two new ones");

    let methods = print_methods("append session", &server);
    for m in [
        "append",
        "updateBlockForPipeline",
        "updatePipeline",
        "getAdditionalDatanode",
        "addBlock",
        "complete",
    ] {
        assert!(methods.contains_key(m), "{m} was not called: {methods:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hadoop_cli_truncates() {
    let server = start(policy(POLICY), None).await;
    let dir = scratch("truncate");
    let data = lines(140000, "cut");
    hdfs_dfs(
        &server,
        "alice",
        &[
            "-D",
            "dfs.blocksize=65536",
            "-put",
            &local(&dir, "cut", &data),
            "/user/alice/cut.txt",
        ],
    )
    .await
    .expect_ok("hdfs dfs -put", &server);

    // Inside block 1: truncate answers false, and -w waits until the block recovery is done.
    let w = hdfs_dfs(
        &server,
        "alice",
        &["-truncate", "-w", "100000", "/user/alice/cut.txt"],
    )
    .await;
    w.expect_ok("hdfs dfs -truncate -w 100000", &server);
    assert!(
        w.stdout.contains("Waiting for") && w.stdout.contains("to length: 100000"),
        "{}",
        w.stdout
    );
    assert_eq!(
        cat(&server, "/user/alice/cut.txt").await,
        text(&data[..100000])
    );
    checksum_is(&server, "/user/alice/cut.txt", &data[..100000]).await;

    // On a block boundary: done at once, nothing to wait for.
    let b = hdfs_dfs(
        &server,
        "alice",
        &["-truncate", "-w", "65536", "/user/alice/cut.txt"],
    )
    .await;
    b.expect_ok("hdfs dfs -truncate -w 65536", &server);
    assert!(
        b.stdout.contains("Truncated") && !b.stdout.contains("Waiting for"),
        "{}",
        b.stdout
    );
    assert_eq!(
        cat(&server, "/user/alice/cut.txt").await,
        text(&data[..65536])
    );

    // Inside a block without -w: Hadoop says to wait, and the file closes on its own.
    let n = hdfs_dfs(
        &server,
        "alice",
        &["-truncate", "1000", "/user/alice/cut.txt"],
    )
    .await;
    n.expect_ok("hdfs dfs -truncate 1000", &server);
    assert!(n.stdout.contains("Wait for block recovery"), "{}", n.stdout);
    let mut length = String::new();
    for _ in 0..10 {
        let s = hdfs_dfs(&server, "alice", &["-stat", "%b", "/user/alice/cut.txt"]).await;
        s.expect_ok("hdfs dfs -stat", &server);
        length = s.stdout.trim().to_string();
        if length == "1000" {
            break;
        }
    }
    assert_eq!(length, "1000");
    assert_eq!(
        cat(&server, "/user/alice/cut.txt").await,
        text(&data[..1000])
    );

    // The model refuses a truncate outside the tree it allows.
    let refused = hdfs_dfs(&server, "alice", &["-truncate", "1", "/README.txt"]).await;
    refused.expect_failure("a truncate of /README.txt", &server);
    assert!(
        refused.stderr.contains("Permission denied by policy"),
        "{}",
        refused.stderr
    );
    assert_eq!(cat(&server, "/README.txt").await, "hello from netget\n");

    let truncates = support::events(&server.state, server.id, "hdfs_truncate").await;
    let seen: Vec<(u64, bool)> = truncates
        .iter()
        .map(|t| {
            (
                t["length"].as_u64().unwrap(),
                t["on_block_boundary"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [(100000, false), (65536, true), (1000, false), (1, false)]
    );
    let methods = print_methods("truncate session", &server);
    assert!(methods.contains_key("truncate"), "{methods:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hadoop_cli_concats() {
    let server = start(policy(POLICY), None).await;
    let dir = scratch("concat");
    let t = lines(65536, "target");
    let s1 = lines(131072, "source1");
    let s2 = lines(5000, "source2");
    hdfs_dfs(&server, "alice", &["-mkdir", "-p", "/tmp/cat"])
        .await
        .expect_ok("hdfs dfs -mkdir -p /tmp/cat", &server);
    for (name, data) in [
        ("t", &t),
        ("s1", &s1),
        ("s2", &s2),
        ("p", &s2),
        ("w", &t),
        ("q", &s2),
    ] {
        hdfs_dfs(
            &server,
            "alice",
            &[
                "-D",
                "dfs.blocksize=65536",
                "-put",
                &local(&dir, name, data),
                &format!("/tmp/cat/{name}"),
            ],
        )
        .await
        .expect_ok(&format!("hdfs dfs -put {name}"), &server);
    }
    hdfs_dfs(
        &server,
        "alice",
        &["-concat", "/tmp/cat/t", "/tmp/cat/s1", "/tmp/cat/s2"],
    )
    .await
    .expect_ok("hdfs dfs -concat", &server);
    let all = [t.as_slice(), s1.as_slice(), s2.as_slice()].concat();
    assert_eq!(cat(&server, "/tmp/cat/t").await, text(&all));
    checksum_is(&server, "/tmp/cat/t", &all).await;
    for gone in ["/tmp/cat/s1", "/tmp/cat/s2"] {
        hdfs_dfs(&server, "alice", &["-test", "-e", gone])
            .await
            .expect_failure(&format!("{gone} after the concat"), &server);
    }

    // A target that is not whole blocks would put a partial block mid-file: this NameNode
    // refuses, saying why (the sources alone would pass: a whole block, then a partial last).
    let partial = hdfs_dfs(
        &server,
        "alice",
        &["-concat", "/tmp/cat/p", "/tmp/cat/w", "/tmp/cat/q"],
    )
    .await;
    partial.expect_failure("a concat onto a partial block", &server);
    assert!(
        partial
            .stderr
            .contains("/tmp/cat/p holds 5000 bytes, not a whole number"),
        "{}",
        partial.stderr
    );
    // Sources from another directory: Hadoop's own rule.
    hdfs_dfs(&server, "alice", &["-mkdir", "/tmp/elsewhere"])
        .await
        .expect_ok("hdfs dfs -mkdir", &server);
    hdfs_dfs(
        &server,
        "alice",
        &[
            "-D",
            "dfs.blocksize=65536",
            "-cp",
            "/tmp/cat/w",
            "/tmp/elsewhere/a",
        ],
    )
    .await
    .expect_ok("hdfs dfs -cp", &server);
    hdfs_dfs(
        &server,
        "alice",
        &[
            "-D",
            "dfs.blocksize=65536",
            "-cp",
            "/tmp/cat/w",
            "/tmp/elsewhere/b",
        ],
    )
    .await
    .expect_ok("hdfs dfs -cp", &server);
    let elsewhere = hdfs_dfs(
        &server,
        "alice",
        &[
            "-concat",
            "/tmp/cat/t",
            "/tmp/elsewhere/a",
            "/tmp/elsewhere/b",
        ],
    )
    .await;
    elsewhere.expect_failure("a concat across directories", &server);
    assert!(
        elsewhere.stderr.contains("is not in the same directory"),
        "{}",
        elsewhere.stderr
    );
    assert_eq!(
        cat(&server, "/tmp/cat/t").await,
        text(&all),
        "unchanged by the refusals"
    );

    let concats = support::events(&server.state, server.id, "hdfs_concat").await;
    assert_eq!(concats.len(), 1, "{concats:?}");
    assert_eq!(
        concats[0]["sources"],
        serde_json::json!(["/tmp/cat/s1", "/tmp/cat/s2"])
    );
    assert_eq!(concats[0]["length"], all.len());
    let methods = print_methods("concat session", &server);
    assert!(methods.contains_key("concat"), "{methods:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

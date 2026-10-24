//! The HDFS server against colinmarc/hdfs v2.4.0 (Go): its own Hadoop RPC, SASL-less handshake,
//! protocol buffer bindings and DataTransferProtocol reader and writer, sharing no code with
//! Hadoop's Java client or with NetGet. The policy in `support.rs` plays the model.
use super::support::{self, go, policy, start, POLICY};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn go_client_reads_writes_and_changes() {
    // A 64 KiB default block size, which getServerDefaults reports and the Go writer adopts.
    let server = start(policy(POLICY), Some(json!({"block_size": 65536}))).await;
    let user = "alice";

    let ls = go(&server, user, &["ls", "-l", "/"], None).await;
    ls.expect_ok("hdfs ls -l /", &server);
    for name in ["README.txt", "data", "big.bin", "user", "tmp"] {
        assert!(ls.stdout.contains(name), "ls lists {name}:\n{}", ls.stdout);
    }
    let readme = ls
        .stdout
        .lines()
        .find(|l| l.ends_with("README.txt"))
        .unwrap();
    assert!(
        readme.starts_with("-rw-r--r--") && readme.contains("alice") && readme.contains("analysts"),
        "{readme}"
    );

    let cat = go(&server, user, &["cat", "/README.txt"], None).await;
    cat.expect_ok("hdfs cat /README.txt", &server);
    assert_eq!(cat.stdout, "hello from netget\n");

    // Three blocks, each read and its chunks checked by Go's own reader.
    let dir = std::env::temp_dir().join(format!(
        "netget-hdfs-go-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let got = dir.join("big.bin");
    go(
        &server,
        user,
        &["get", "/big.bin", &got.to_string_lossy()],
        None,
    )
    .await
    .expect_ok("hdfs get /big.bin", &server);
    assert_eq!(std::fs::read(&got).unwrap(), support::big_bin());

    let sum = go(&server, user, &["checksum", "/big.bin"], None).await;
    sum.expect_ok("hdfs checksum /big.bin", &server);
    assert_eq!(
        sum.stdout.trim(),
        format!(
            "{} /big.bin",
            hex::encode(support::md5md5crc32c(&support::big_bin(), 65536))
        )
    );

    // Writes: mkdir, put (three blocks at the server's 64 KiB default), read back, mv, rm.
    go(&server, user, &["mkdir", "-p", "/user/alice/go/deep"], None)
        .await
        .expect_ok("hdfs mkdir -p", &server);
    let local = dir.join("go-upload.bin");
    let content: Vec<u8> = (0..150_000u32).map(|i| (i * 7 % 256) as u8).collect();
    std::fs::write(&local, &content).unwrap();
    go(
        &server,
        user,
        &["put", &local.to_string_lossy(), "/user/alice/go/up.bin"],
        None,
    )
    .await
    .expect_ok("hdfs put", &server);
    let back = dir.join("back.bin");
    go(
        &server,
        user,
        &["get", "/user/alice/go/up.bin", &back.to_string_lossy()],
        None,
    )
    .await
    .expect_ok("hdfs get of the upload", &server);
    assert_eq!(std::fs::read(&back).unwrap(), content);
    let sum = go(&server, user, &["checksum", "/user/alice/go/up.bin"], None).await;
    sum.expect_ok("hdfs checksum of the upload", &server);
    assert!(
        sum.stdout
            .starts_with(&hex::encode(support::md5md5crc32c(&content, 65536))),
        "{}",
        sum.stdout
    );
    go(
        &server,
        user,
        &["mv", "/user/alice/go/up.bin", "/user/alice/moved.bin"],
        None,
    )
    .await
    .expect_ok("hdfs mv", &server);
    go(&server, user, &["rm", "-r", "/user/alice/go"], None)
        .await
        .expect_ok("hdfs rm -r", &server);
    let after = go(&server, user, &["ls", "/user/alice"], None).await;
    after.expect_ok("hdfs ls /user/alice", &server);
    assert!(
        after.stdout.contains("moved.bin") && !after.stdout.contains("go\n"),
        "{}",
        after.stdout
    );

    // The model refuses a change outside the allowed tree.
    let refused = go(&server, "bob", &["mkdir", "/data/go"], None).await;
    refused.expect_failure("mkdir /data/go as bob", &server);
    assert!(
        refused.stderr.contains("permission denied")
            || refused.stderr.contains("Permission denied"),
        "{}",
        refused.stderr
    );

    let writes = support::events(&server.state, server.id, "hdfs_write").await;
    assert_eq!(writes.len(), 1, "{writes:?}");
    assert_eq!(writes[0]["length"], 150_000);
    assert_eq!(writes[0]["blocks"], 3);
    assert_eq!(writes[0]["encoding"], "hex");

    let methods = server.methods();
    println!("Go client: NameNode methods {methods:?}");
    println!("Go client: DataNode ops {:?}", server.ops());
    for m in [
        "getListing",
        "getFileInfo",
        "getBlockLocations",
        "mkdirs",
        "create",
        "addBlock",
        "complete",
        "delete",
    ] {
        assert!(methods.contains_key(m), "{m} was not called: {methods:?}");
    }
    assert!(
        methods.contains_key("rename") || methods.contains_key("rename2"),
        "{methods:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// colinmarc/hdfs's append (its library's `Client.Append`, through the driver in `goappend`)
/// and its `truncate` command. Its writer aligns to the next chunk with a small first packet
/// and checksums it alone, calls updateBlockForPipeline when the reopened block is done, and
/// completes with the generation stamp it started with; its truncate does not wait, so the
/// test polls `ls` until the block recovery has finished.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn go_client_appends_and_truncates() {
    let server = start(policy(POLICY), Some(json!({"block_size": 65536}))).await;
    let user = "alice";
    let dir = std::env::temp_dir().join(format!(
        "netget-hdfs-go-append-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    // 150 000 bytes: block 2 holds 18 928, its last chunk 496 of 512.
    let first: Vec<u8> = (0..150_000u32).map(|i| (i * 13 % 251) as u8).collect();
    let local = dir.join("first.bin");
    std::fs::write(&local, &first).unwrap();
    go(
        &server,
        user,
        &["put", &local.to_string_lossy(), "/user/alice/grow.bin"],
        None,
    )
    .await
    .expect_ok("hdfs put", &server);
    // 100 000 more: 16 bytes finish the chunk, block 2 fills, block 3 holds the rest.
    let more: Vec<u8> = (0..100_000u32).map(|i| (i * 7 % 241) as u8).collect();
    let appended = support::go_append_to(&server, user, "/user/alice/grow.bin", more.clone()).await;
    appended.expect_ok("colinmarc/hdfs Client.Append", &server);
    assert!(
        appended.stdout.contains("appended 100000 bytes"),
        "{}",
        appended.stdout
    );
    let all = [first.as_slice(), more.as_slice()].concat();
    let back = dir.join("back.bin");
    go(
        &server,
        user,
        &["get", "/user/alice/grow.bin", &back.to_string_lossy()],
        None,
    )
    .await
    .expect_ok("hdfs get of the appended file", &server);
    assert_eq!(std::fs::read(&back).unwrap(), all);
    let sum = go(&server, user, &["checksum", "/user/alice/grow.bin"], None).await;
    sum.expect_ok("hdfs checksum of the appended file", &server);
    assert!(
        sum.stdout
            .starts_with(&hex::encode(support::md5md5crc32c(&all, 65536))),
        "{}",
        sum.stdout
    );

    // truncate inside block 3: Go does not wait; ls reports the old length until recovery ends.
    go(
        &server,
        user,
        &["truncate", "200000", "/user/alice/grow.bin"],
        None,
    )
    .await
    .expect_ok("hdfs truncate 200000", &server);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let ls = go(&server, user, &["ls", "-l", "/user/alice/grow.bin"], None).await;
        ls.expect_ok("hdfs ls -l", &server);
        if ls.stdout.contains(" 200000 ") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "recovery never finished: {}",
            ls.stdout
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let cut = dir.join("cut.bin");
    go(
        &server,
        user,
        &["get", "/user/alice/grow.bin", &cut.to_string_lossy()],
        None,
    )
    .await
    .expect_ok("hdfs get of the truncated file", &server);
    assert_eq!(std::fs::read(&cut).unwrap(), &all[..200_000]);
    // On a block boundary: done at once.
    go(
        &server,
        user,
        &["truncate", "131072", "/user/alice/grow.bin"],
        None,
    )
    .await
    .expect_ok("hdfs truncate 131072", &server);
    let sum = go(&server, user, &["checksum", "/user/alice/grow.bin"], None).await;
    sum.expect_ok("hdfs checksum after the boundary truncate", &server);
    assert!(
        sum.stdout
            .starts_with(&hex::encode(support::md5md5crc32c(&all[..131_072], 65536))),
        "{}",
        sum.stdout
    );
    // The model refuses an append outside the tree it allows.
    let refused = support::go_append_to(&server, "bob", "/data/events.csv", b"x".to_vec()).await;
    refused.expect_failure("an append to /data", &server);

    let appends = support::events(&server.state, server.id, "hdfs_append").await;
    assert_eq!(appends[0]["length"], 150_000);
    assert_eq!(appends[0]["last_block_partial"], true);
    assert_eq!(appends[0]["new_block"], false, "colinmarc sends no flag");
    let writes = support::events(&server.state, server.id, "hdfs_write").await;
    let w = writes
        .iter()
        .find(|w| w["append"] == true)
        .expect("the appended bytes were decided");
    assert_eq!(
        (w["offset"].as_u64(), w["length"].as_u64()),
        (Some(150_000), Some(100_000))
    );

    let methods = server.methods();
    println!("Go client (append, truncate): NameNode methods {methods:?}");
    println!(
        "Go client (append, truncate): DataNode ops {:?}",
        server.ops()
    );
    for m in [
        "append",
        "updateBlockForPipeline",
        "addBlock",
        "complete",
        "truncate",
    ] {
        assert!(methods.contains_key(m), "{m} was not called: {methods:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

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
    let readme = ls.stdout.lines().find(|l| l.ends_with("README.txt")).unwrap();
    assert!(
        readme.starts_with("-rw-r--r--") && readme.contains("alice") && readme.contains("analysts"),
        "{readme}"
    );

    let cat = go(&server, user, &["cat", "/README.txt"], None).await;
    cat.expect_ok("hdfs cat /README.txt", &server);
    assert_eq!(cat.stdout, "hello from netget\n");

    // Three blocks, each read and its chunks checked by Go's own reader.
    let dir = std::env::temp_dir().join(format!("netget-hdfs-go-{}-{}", std::process::id(), uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir).unwrap();
    let got = dir.join("big.bin");
    go(&server, user, &["get", "/big.bin", &got.to_string_lossy()], None)
        .await
        .expect_ok("hdfs get /big.bin", &server);
    assert_eq!(std::fs::read(&got).unwrap(), support::big_bin());

    let sum = go(&server, user, &["checksum", "/big.bin"], None).await;
    sum.expect_ok("hdfs checksum /big.bin", &server);
    assert_eq!(
        sum.stdout.trim(),
        format!("{} /big.bin", hex::encode(support::md5md5crc32c(&support::big_bin(), 65536)))
    );

    // Writes: mkdir, put (three blocks at the server's 64 KiB default), read back, mv, rm.
    go(&server, user, &["mkdir", "-p", "/user/alice/go/deep"], None)
        .await
        .expect_ok("hdfs mkdir -p", &server);
    let local = dir.join("go-upload.bin");
    let content: Vec<u8> = (0..150_000u32).map(|i| (i * 7 % 256) as u8).collect();
    std::fs::write(&local, &content).unwrap();
    go(&server, user, &["put", &local.to_string_lossy(), "/user/alice/go/up.bin"], None)
        .await
        .expect_ok("hdfs put", &server);
    let back = dir.join("back.bin");
    go(&server, user, &["get", "/user/alice/go/up.bin", &back.to_string_lossy()], None)
        .await
        .expect_ok("hdfs get of the upload", &server);
    assert_eq!(std::fs::read(&back).unwrap(), content);
    let sum = go(&server, user, &["checksum", "/user/alice/go/up.bin"], None).await;
    sum.expect_ok("hdfs checksum of the upload", &server);
    assert!(
        sum.stdout.starts_with(&hex::encode(support::md5md5crc32c(&content, 65536))),
        "{}",
        sum.stdout
    );
    go(&server, user, &["mv", "/user/alice/go/up.bin", "/user/alice/moved.bin"], None)
        .await
        .expect_ok("hdfs mv", &server);
    go(&server, user, &["rm", "-r", "/user/alice/go"], None)
        .await
        .expect_ok("hdfs rm -r", &server);
    let after = go(&server, user, &["ls", "/user/alice"], None).await;
    after.expect_ok("hdfs ls /user/alice", &server);
    assert!(after.stdout.contains("moved.bin") && !after.stdout.contains("go\n"), "{}", after.stdout);

    // The model refuses a change outside the allowed tree.
    let refused = go(&server, "bob", &["mkdir", "/data/go"], None).await;
    refused.expect_failure("mkdir /data/go as bob", &server);
    assert!(refused.stderr.contains("permission denied") || refused.stderr.contains("Permission denied"), "{}", refused.stderr);

    let writes = support::events(&server.state, server.id, "hdfs_write").await;
    assert_eq!(writes.len(), 1, "{writes:?}");
    assert_eq!(writes[0]["length"], 150_000);
    assert_eq!(writes[0]["blocks"], 3);
    assert_eq!(writes[0]["encoding"], "hex");

    let methods = server.methods();
    println!("Go client: NameNode methods {methods:?}");
    println!("Go client: DataNode ops {:?}", server.ops());
    for m in ["getListing", "getFileInfo", "getBlockLocations", "mkdirs", "create", "addBlock", "complete", "delete"] {
        assert!(methods.contains_key(m), "{m} was not called: {methods:?}");
    }
    assert!(methods.contains_key("rename") || methods.contains_key("rename2"), "{methods:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

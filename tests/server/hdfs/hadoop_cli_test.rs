//! The HDFS server against Apache Hadoop 3.5.0's own `hdfs dfs` CLI: Hadoop's Java DFSClient,
//! which is the client HDFS is written for. Every command runs as a separate JVM against the
//! in-process NameNode; the python policy in `support.rs` plays the model.
use super::support::{self, hdfs_dfs, policy, start, POLICY};
use std::collections::BTreeMap;

/// The methods a client sent, printed so a reader can count them against the ones implemented.
fn print_methods(what: &str, server: &support::Started) -> BTreeMap<String, u64> {
    let methods = server.methods();
    let ops = server.ops();
    println!("{what}: NameNode methods {methods:?}");
    println!("{what}: DataNode ops {ops:?}");
    methods
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hadoop_cli_reads_the_described_namespace() {
    let server = start(policy(POLICY), None).await;
    let user = "alice";

    let ls = hdfs_dfs(&server, user, &["-ls", "/"]).await;
    ls.expect_ok("hdfs dfs -ls /", &server);
    for name in ["/README.txt", "/data", "/big.bin", "/user", "/tmp"] {
        assert!(
            ls.stdout.contains(name),
            "ls / lists {name}:\n{}",
            ls.stdout
        );
    }
    let readme = ls
        .stdout
        .lines()
        .find(|l| l.ends_with("/README.txt"))
        .expect("a README line");
    assert!(
        readme.starts_with("-rw-r--r--")
            && readme.contains(" alice analysts ")
            && readme.contains(" 18 "),
        "README's mode, owner, group and length: {readme}"
    );
    let big = ls.stdout.lines().find(|l| l.ends_with("/big.bin")).unwrap();
    assert!(
        big.contains("   3 alice") || big.contains(" 3 "),
        "replication 3: {big}"
    );

    let cat = hdfs_dfs(&server, user, &["-cat", "/README.txt"]).await;
    cat.expect_ok("hdfs dfs -cat /README.txt", &server);
    assert_eq!(cat.stdout, "hello from netget\n");

    let stat = hdfs_dfs(
        &server,
        user,
        &["-stat", "%n %b %o %r %u %g %F", "/big.bin"],
    )
    .await;
    stat.expect_ok("hdfs dfs -stat", &server);
    assert_eq!(
        stat.stdout.trim(),
        "big.bin 180000 65536 3 hdfs supergroup regular file"
    );

    print_methods("read-only session", &server);
}

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "netget-hdfs-{name}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hadoop_cli_gets_blocks_checksums_and_summaries() {
    let server = start(policy(POLICY), None).await;
    let user = "alice";
    let dir = scratch("get");
    let local = dir.join("big.bin");
    let local_s = local.to_string_lossy().into_owned();

    // Three 64 KiB blocks, each read from the DataNode with its CRC32C chunks checked by Java.
    hdfs_dfs(&server, user, &["-get", "/big.bin", &local_s])
        .await
        .expect_ok("hdfs dfs -get /big.bin", &server);
    assert_eq!(std::fs::read(&local).unwrap(), support::big_bin());

    // -checksum: MD5 of the per-block MD5s of the chunk CRC32Cs, computed here independently.
    let sum = hdfs_dfs(&server, user, &["-checksum", "/big.bin"]).await;
    sum.expect_ok("hdfs dfs -checksum", &server);
    let expected = hex::encode(support::md5md5crc32c(&support::big_bin(), 65536));
    assert!(
        sum.stdout.contains("MD5-of-128MD5-of-512CRC32C") && sum.stdout.contains(&expected),
        "checksum {expected}: {}",
        sum.stdout
    );

    // -du and -count read getContentSummary over the whole tree.
    let du = hdfs_dfs(&server, user, &["-du", "-s", "/data"]).await;
    du.expect_ok("hdfs dfs -du -s /data", &server);
    assert!(
        du.stdout.trim_start().starts_with("24 "),
        "du /data: {}",
        du.stdout
    );
    let count = hdfs_dfs(&server, user, &["-count", "/data"]).await;
    count.expect_ok("hdfs dfs -count /data", &server);
    let fields: Vec<&str> = count.stdout.split_whitespace().collect();
    assert_eq!(
        &fields[..3],
        ["1", "2", "24"],
        "count /data: {}",
        count.stdout
    );

    // -test: exists, directory, file, zero length, non-empty.
    for (flag, path, ok) in [
        ("-e", "/README.txt", true),
        ("-e", "/nope", false),
        ("-d", "/data", true),
        ("-d", "/README.txt", false),
        ("-f", "/README.txt", true),
        ("-z", "/data/empty.txt", true),
        ("-s", "/README.txt", true),
        ("-s", "/data/empty.txt", false),
    ] {
        let r = hdfs_dfs(&server, user, &["-test", flag, path]).await;
        assert_eq!(r.ok(), ok, "-test {flag} {path}: {r:?}");
    }

    // A described failing region: the DataNode ends the transfer and the read fails.
    let broken = hdfs_dfs(&server, user, &["-cat", "/broken.bin"]).await;
    broken.expect_failure("hdfs dfs -cat /broken.bin", &server);

    // A missing file is Hadoop's own FileNotFoundException.
    let missing = hdfs_dfs(&server, user, &["-cat", "/nope.txt"]).await;
    missing.expect_failure("hdfs dfs -cat /nope.txt", &server);
    assert!(
        missing.stderr.contains("No such file or directory"),
        "{}",
        missing.stderr
    );

    print_methods("get/checksum/summary session", &server);
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hadoop_cli_changes_go_through_the_model() {
    let server = start(policy(POLICY), None).await;
    let user = "alice";
    let dir = scratch("put");
    let local = dir.join("upload.txt");
    let text = "uploaded through Hadoop's DataStreamer\n".repeat(4000);
    std::fs::write(&local, &text).unwrap();
    let local_s = local.to_string_lossy().into_owned();

    // mkdir, put (create, addBlock ×3 at a 64 KiB block size, the pipeline, complete, then
    // rename from ._COPYING_), cat back, mv, chmod, rm.
    hdfs_dfs(&server, user, &["-mkdir", "-p", "/user/alice/reports/2026"])
        .await
        .expect_ok("hdfs dfs -mkdir -p", &server);
    hdfs_dfs(
        &server,
        user,
        &[
            "-D",
            "dfs.blocksize=65536",
            "-put",
            &local_s,
            "/user/alice/reports/2026/up.txt",
        ],
    )
    .await
    .expect_ok("hdfs dfs -put", &server);
    let cat = hdfs_dfs(&server, user, &["-cat", "/user/alice/reports/2026/up.txt"]).await;
    cat.expect_ok("hdfs dfs -cat the uploaded file", &server);
    assert_eq!(cat.stdout, text);
    let stat = hdfs_dfs(
        &server,
        user,
        &["-stat", "%b %o %u", "/user/alice/reports/2026/up.txt"],
    )
    .await;
    stat.expect_ok("hdfs dfs -stat", &server);
    assert_eq!(stat.stdout.trim(), format!("{} 65536 alice", text.len()));
    let sum = hdfs_dfs(
        &server,
        user,
        &["-checksum", "/user/alice/reports/2026/up.txt"],
    )
    .await;
    sum.expect_ok("hdfs dfs -checksum of the upload", &server);
    assert!(
        sum.stdout
            .contains(&hex::encode(support::md5md5crc32c(text.as_bytes(), 65536))),
        "{}",
        sum.stdout
    );

    hdfs_dfs(
        &server,
        user,
        &[
            "-mv",
            "/user/alice/reports/2026/up.txt",
            "/user/alice/up-moved.txt",
        ],
    )
    .await
    .expect_ok("hdfs dfs -mv", &server);
    hdfs_dfs(
        &server,
        user,
        &["-chmod", "600", "/user/alice/up-moved.txt"],
    )
    .await
    .expect_ok("hdfs dfs -chmod", &server);
    let ls = hdfs_dfs(&server, user, &["-ls", "/user/alice"]).await;
    ls.expect_ok("hdfs dfs -ls /user/alice", &server);
    let moved = ls
        .stdout
        .lines()
        .find(|l| l.ends_with("/user/alice/up-moved.txt"))
        .unwrap_or_else(|| panic!("{}", ls.stdout));
    assert!(moved.starts_with("-rw-------"), "{moved}");
    assert!(
        ls.stdout.contains("/user/alice/notes.txt"),
        "the described file is still there: {}",
        ls.stdout
    );
    hdfs_dfs(&server, user, &["-rm", "-r", "/user/alice/reports"])
        .await
        .expect_ok("hdfs dfs -rm -r", &server);
    hdfs_dfs(&server, user, &["-test", "-e", "/user/alice/reports"])
        .await
        .expect_failure("the removed directory", &server);

    // The model's decisions, in order, as it saw them.
    let creates = support::events(&server.state, server.id, "hdfs_create").await;
    assert_eq!(creates.len(), 1, "{creates:?}");
    assert_eq!(
        creates[0]["path"],
        "/user/alice/reports/2026/up.txt._COPYING_"
    );
    assert_eq!(creates[0]["block_size"], 65536);
    let writes = support::events(&server.state, server.id, "hdfs_write").await;
    assert_eq!(writes.len(), 1);
    assert_eq!(writes[0]["length"], text.len());
    assert_eq!(writes[0]["blocks"], text.len().div_ceil(65536));
    assert_eq!(writes[0]["encoding"], "utf8");
    assert_eq!(writes[0]["data_truncated"], true);
    assert!(writes[0]["data"]
        .as_str()
        .unwrap()
        .starts_with("uploaded through"));
    let renames = support::events(&server.state, server.id, "hdfs_rename").await;
    assert_eq!(
        renames.len(),
        2,
        "the ._COPYING_ rename and the mv: {renames:?}"
    );
    assert_eq!(renames[1]["destination"], "/user/alice/up-moved.txt");
    let chmods = support::events(&server.state, server.id, "hdfs_set_permission").await;
    assert_eq!(chmods[0]["mode"], 0o600);
    assert_eq!(
        support::events(&server.state, server.id, "hdfs_delete")
            .await
            .len(),
        1
    );

    let methods = print_methods("change session", &server);
    for m in [
        "mkdirs",
        "create",
        "addBlock",
        "complete",
        "rename",
        "setPermission",
        "delete",
    ] {
        assert!(methods.contains_key(m), "{m} was not called: {methods:?}");
    }
    assert!(
        server.ops().get("WRITE_BLOCK").copied().unwrap_or(0) >= 3,
        "{:?}",
        server.ops()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hadoop_cli_sees_the_models_refusals() {
    let server = start(policy(POLICY), None).await;
    let dir = scratch("deny");
    let local = dir.join("bad.txt");
    std::fs::write(&local, "this is forbidden content\n").unwrap();
    let local_s = local.to_string_lossy().into_owned();

    // A user the model refuses.
    let mallory = hdfs_dfs(&server, "mallory", &["-ls", "/"]).await;
    mallory.expect_failure("ls as mallory", &server);
    assert!(
        mallory.stderr.contains("mallory is not welcome"),
        "{}",
        mallory.stderr
    );
    // A change outside the allowed tree: AccessControlException with the model's message.
    let mkdir = hdfs_dfs(&server, "bob", &["-mkdir", "/data/new"]).await;
    mkdir.expect_failure("mkdir /data/new", &server);
    assert!(
        mkdir.stderr.contains("Permission denied by policy"),
        "{}",
        mkdir.stderr
    );
    hdfs_dfs(&server, "bob", &["-test", "-e", "/data/new"])
        .await
        .expect_failure("the refused mkdir left nothing", &server);
    // Content the model refuses: the put fails with the model's exception, nothing is kept.
    let put = hdfs_dfs(&server, "alice", &["-put", &local_s, "/tmp/bad.txt"]).await;
    put.expect_failure("put of refused content", &server);
    assert!(
        put.stderr.contains("put:") && put.stderr.contains("the model refuses this content"),
        "{}",
        put.stderr
    );
    hdfs_dfs(&server, "alice", &["-test", "-e", "/tmp/bad.txt"])
        .await
        .expect_failure("the refused file", &server);
    // A directory the model will not describe, and one it does not answer for.
    let secret = hdfs_dfs(&server, "alice", &["-ls", "/secret"]).await;
    secret.expect_failure("ls /secret", &server);
    assert!(
        secret
            .stderr
            .contains("the model will not say what is in /secret"),
        "{}",
        secret.stderr
    );
    let silent = hdfs_dfs(&server, "alice", &["-ls", "/silent"]).await;
    silent.expect_failure("ls /silent", &server);
    assert!(
        server
            .lines("decision=model_silent")
            .iter()
            .any(|l| l.contains("/silent")),
        "{}",
        server.dump_logs()
    );
    print_methods("refusal session", &server);
    let _ = std::fs::remove_dir_all(&dir);
}

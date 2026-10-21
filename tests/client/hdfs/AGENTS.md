# HDFS client tests

4 tests, all passing on macOS, none `#[ignore]`d. 4 in `real_server_test.rs`.

The peer is a real single-node HDFS from Apache Hadoop 3.5.0 (`sh
tests/client/yarn/install_peers.sh <dir>`, `NETGET_HADOOP_HOME`, a JDK 17 on `JAVA_HOME`;
without them every test fails and says so). `Cluster::start` writes a configuration into the
NameNode's temporary directory — every address on 127.0.0.1 and a probed port, no safe-mode
extension, 64 KiB blocks allowed — runs `hdfs namenode -format`, then a NameNode (ready on
`NameNode RPC up at`) and a DataNode sharing its configuration (ready on `successfully
registered with NN`), and waits for `dfsadmin -safemode wait`. The NameNode runs with
`HDFS_AUDIT_LOGGER=INFO,console`, so its audit log — one line per call that reached it, with
`ugi=`, `cmd=`, `src=` and `dst=` — is on its stdout, which `RealServer` keeps. Both daemons'
logs print when a test fails.

The model is a python policy per test; nothing reaches a real LLM.

| test | asserts |
|---|---|
| `hdfs_client_drives_a_real_cluster` | a twelve-step session: the server defaults (CRC32C), a listing of what `hdfs dfs -put` seeded (names, lengths, block size, owner), a stat, a text read, a hex read straddling a block boundary (two DataNode reads, bytes exact), mkdir, a small write and a three-block write at a 64 KiB block size (read back with `hdfs dfs -cat` and `-stat`), rename, chmod (640 by `-stat %a`), a recursive delete, a stat that finds nothing, and a read of a missing file arriving as `java.io.FileNotFoundException`; every change in the NameNode's audit log |
| `the_namenodes_refusal_reaches_the_model` | as `mallory`, mkdir and write under a 755 directory owned by someone else arrive as `org.apache.hadoop.security.AccessControlException` with HDFS's own message; the mkdir is in the audit log as refused |
| `followup_chain_stops_at_the_bound` | a model that stats `/` after every result: `decision=followup_depth`, exactly `MAX_FOLLOWUP_DEPTH` stats raised and audited |
| `llm_failure_sends_nothing` | no handler and no backend: `decision=fail_closed_llm_error` and nothing in the audit log |

Mutation-checked: dropping the model's actions in the dispatcher fails
`hdfs_client_drives_a_real_cluster` (no listing) and `followup_chain_stops_at_the_bound`.

```bash
./cargo-isolated.sh test --no-default-features --test client -- client::hdfs:: --test-threads=2
```

About 15 s with two threads on an M-series Mac; each test runs its own NameNode and DataNode.

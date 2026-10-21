# HDFS server tests

11 tests, all passing on macOS, none `#[ignore]`d. 4 in `hadoop_cli_test.rs`, 1 in `go_client_test.rs`, 6 in `wire_test.rs`.

Every test starts the server in-process on loopback with an unreachable model; a python policy
(`support.rs`, `POLICY`) answers as the model, so an event it does not cover is the fail-closed
path. `support.rs` also keeps every status line the server logs: the per-connection summaries
(`HDFS NameNode connection … closed after N calls: method=count …`, `HDFS DataNode connection
… closed: OP=count …`) are how each test counts the methods and ops a client sent, and each
peer test prints them.

## Peers (required: a test fails, naming how to install them, when they are absent)

- **Apache Hadoop 3.5.0's `hdfs dfs`** (Java): `sh tests/client/yarn/install_peers.sh <dir>`,
  `export NETGET_HADOOP_HOME=<dir>/hadoop-3.5.0`, and a JDK 17 on `JAVA_HOME`. Each command is
  its own JVM, run with `fs.defaultFS=hdfs://127.0.0.1:<port>` and `HADOOP_USER_NAME`.
- **colinmarc/hdfs v2.4.0** (Go): `go install github.com/colinmarc/hdfs/v2/cmd/hdfs@v2.4.0`,
  `export NETGET_GO_HDFS=$(go env GOPATH)/bin/hdfs`; it is pointed at the server with
  `HADOOP_NAMENODE`.
- **tshark** for the oracle in `wire_test.rs`.

## What each file pins

`hadoop_cli_test.rs` — 4 tests: ls (modes, owners, groups, lengths, replication), cat, stat;
get of a three-block file byte for byte, checksum (MD5 of the block MD5s of the chunk CRC32Cs,
computed in `support.rs` with Hadoop's own padding quirk), du and count (getContentSummary),
test -e/-d/-f/-z/-s, a described failing region failing the read, a missing file; mkdir -p,
put of a three-block file at a 64 KiB block size (create, addBlock ×3, WRITE_BLOCK ×3,
complete, the `._COPYING_` rename), cat and checksum of it, mv, chmod, rm -r, and the events
the model saw for each; a refused user, a refused mkdir, refused content (nothing kept), a
directory the model will not describe, and one it does not answer for.

`go_client_test.rs` — 1 test: ls -l, cat, get and checksum of the three-block file, mkdir -p,
put of 150 000 bytes in three blocks at the server's 64 KiB default (with Go's
updateBlockForPipeline after each), get and checksum of the upload, mv, rm -r, a refused mkdir.

`wire_test.rs` — 6 tests, a raw client writing every request by hand: pipelined calls answered
in order with their call ids and the client id echoed, a missing path, FileNotFoundException,
RpcNoSuchMethodException, a listing after `startAfter`, a READ_BLOCK whose CRC32Cs are checked
here, and the pcap oracle; the RPC frame bound (bound + 1 refused FATAL from the length, before
and after the connection context; exactly the bound read whole); not-hrpc, a wrong IPC
version, SASL NEGOTIATE answered SIMPLE and Kerberos refused; a model that fails refusing the
connection and a model that does not describe exposing nothing; a write with a wrong chunk
checksum answered ERROR_CHECKSUM and not kept, the same block written right and read back, a
refused write leaving getFsStats' `used` unchanged and the file empty, a packet over the bound,
an unsupported op and an old version; refused and Rust-refused changes leaving the namespace
alone, and `read_only` refusing without asking.

## What tshark can and cannot check

`hdfs` and `hdfsdata` (present in 4.2.2 and 4.6) were written for Hadoop 1's Writable RPC. On
Hadoop 3 traffic `hdfs` reads the connection header (`hdfs.type` hrpc, `hdfs.version` 9,
`hdfs.auth_type` 0) and every frame reaches it; `hdfsdata` reads the op header
(`hdfsdata.version` 28, `hdfsdata.cmd` 81) of a READ_BLOCK. Both report the protocol buffers
after that as malformed, which is a statement about the dissectors, so the oracle asserts the
fields they read rather than a clean expert log. The DataTransfer packets and checksums are
checked by the raw client's own CRC32C and by both independent clients.

## Mutation-checked

Each applied alone, the named test failing on its own assertion, then reverted: the RPC frame
length bound (`rpc_frames_over_the_bound_are_refused_from_their_length` waits for a body that
never comes); checksum verification on write (`writes_are_checksummed_and_decided` gets SUCCESS
acks); admitting a user when the model fails (`model_failure_exposes_nothing` gets an ERROR
instead of FATAL); committing a refused write (`writes_are_checksummed_and_decided` sees the
overlay grow); answering each call with the previous call id
(`raw_session_answers_every_call_by_its_id`, and Hadoop's own client fails
`hadoop_cli_reads_the_described_namespace`).

## Running

```bash
export NETGET_HADOOP_HOME=/tmp/hadoop-peers/hadoop-3.5.0 JAVA_HOME=<a JDK 17>
export NETGET_GO_HDFS=$(go env GOPATH)/bin/hdfs
./cargo-isolated.sh test --no-default-features --test server -- server::hdfs:: --test-threads=4
```

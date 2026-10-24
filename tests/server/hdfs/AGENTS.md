# HDFS server tests

27 tests, all passing on macOS, none `#[ignore]`d. 4 in `hadoop_cli_test.rs`, 3 in `hadoop_cli_mutation_test.rs`, 2 in `go_client_test.rs`, 7 in `wire_test.rs`, 5 in `mutation_wire_test.rs`, 6 in `deadline_test.rs`.

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
  `HADOOP_NAMENODE`. Its `hdfs` command has no append, so `goappend/` (go.mod and go.sum pin
  v2.4.0) is a driver that calls the library's own `Client.Append` and nothing else: `(cd
  tests/server/hdfs/goappend && go build -o $(go env GOPATH)/bin/netget-hdfs-append .)`, found
  beside `NETGET_GO_HDFS` or at `NETGET_GO_HDFS_APPEND`. colinmarc/hdfs has no concat at all.
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

`hadoop_cli_mutation_test.rs` — 3 tests. **appends**: `-appendToFile` of 130 000 bytes onto a
70 000-byte file at 64 KiB blocks (its last chunk 368 of 512 bytes: the partial chunk continued
alone, the block filled, two blocks added), read back with `-cat`, `-stat` and `-checksum`
against the checksum computed here; an append after a full block (no block reopened), then one
with the replace-datanode policy ALWAYS at replication 2, which calls getAdditionalDatanode;
`-appendToFile -n` after a partial block refused; an append the model refuses and content it
refuses (nothing kept). **truncates**: `-truncate -w` inside a block (stdout "Waiting for …",
then the cut file and its checksum), on a block boundary (no waiting), without `-w` (Hadoop's
"Wait for block recovery" message, then the file closes on its own), and one the model refuses.
**concats**: `-concat` of a two-block and a partial source onto a one-block target (`-cat`,
`-checksum`, the sources gone), a partial target refused by this NameNode with the reason, and
sources from another directory refused by Hadoop's own rule.

`go_client_test.rs` — 2 tests. The first: ls -l, cat, get and checksum of the three-block file,
mkdir -p, put of 150 000 bytes in three blocks at the server's 64 KiB default (with Go's
updateBlockForPipeline after each), get and checksum of the upload, mv, rm -r, a refused mkdir.
The second: Client.Append of 100 000 bytes onto 150 000 (Go's first packet aligns to the chunk
boundary on its own, and it runs the append pipeline under the block's old generation stamp),
get and checksum; `truncate` inside a block (Go does not wait: `ls -l` is polled until the
recovery ends) and on a boundary, each read back; an append the model refuses.

`wire_test.rs` — 7 tests, a raw client writing every request by hand: pipelined calls answered
in order with their call ids and the client id echoed, a missing path, FileNotFoundException,
RpcNoSuchMethodException, a listing after `startAfter`, a READ_BLOCK whose CRC32Cs are checked
here, and the pcap oracle; the RPC frame bound (bound + 1 refused FATAL from the length, before
and after the connection context; exactly the bound read whole); not-hrpc, a wrong IPC
version, SASL NEGOTIATE answered SIMPLE and Kerberos refused; a request of ten thousand nested
groups refused as malformed (prost stops at 100 levels) with the server alive for the next call; a model that fails refusing the
connection and a model that does not describe exposing nothing; a write with a wrong chunk
checksum answered ERROR_CHECKSUM and not kept, the same block written right and read back, a
refused write leaving getFsStats' `used` unchanged and the file empty, a packet over the bound,
an unsupported op and an old version; refused and Rust-refused changes leaving the namespace
alone, and `read_only` refusing without asking.

`mutation_wire_test.rs` — 5 tests, the raw client again. **append_continues_the_partial_last_chunk**:
append answers the partial block with its length; the DataNode refuses an append naming the
wrong length, a generation stamp nobody offered, or the create stage; updateBlockForPipeline
offers a newer stamp and updatePipeline adopts it; a first packet whose CRC32C covers the whole
chunk (old and new bytes) is ERROR_CHECKSUM and one crossing the chunk's end ERROR_INVALID; the
right packets are acked and complete commits; every chunk read back is checked against a CRC32C
computed here over old and new bytes; NEW_BLOCK refused; content the model refuses leaves the
file as it was. **append_on_a_block_boundary_and_its_refusals**: no block reopened after a full
block, the next block at 65536; a missing file, a directory and a file another writer holds
refused before the model; one the model refuses. **truncate_inside_a_block_goes_through_recovery**:
longer refused, same length true without asking; inside a block false, open, old length
reported, locations ending at the new length; the same length again false without asking,
another length and an append refused; closed after recovery with the bytes cut; a boundary
truncate true at once. **concat_preconditions_are_refused_before_the_model**: ten refusals —
Hadoop's (no sources, other directory, the target itself, a source twice, empty, a larger
block size, missing) and this NameNode's (another block size, a partial target, a partial
source not last) — and an open source, none reaching the model; then a concat whose bytes and
removed sources are read back. **new_mutations_fail_closed_without_an_answer**: append, truncate
and concat with a model that answers nothing are IOException, `decision=model_silent`, nothing
changed.

`deadline_test.rs` — 6 tests, one per deadline parameter (the DataNode's first op and its frame
share a test): the deadline under test at 2 s and every other at 600 s, a peer that stalls
(nothing; the header without the context; half a frame; idle after a call; one byte of an op;
idle after a read; a write with no packet) is closed no earlier than 2 s and well before the
default, and the log names the deadline.

## What tshark can and cannot check

`hdfs` and `hdfsdata` (present in 4.2.2 and 4.6) were written for Hadoop 1's Writable RPC. On
Hadoop 3 traffic `hdfs` reads the connection header (`hdfs.type` hrpc, `hdfs.version` 9,
`hdfs.auth_type` 0) and every frame reaches it; `hdfsdata` reads the op header
(`hdfsdata.version` 28, `hdfsdata.cmd` 81) of a READ_BLOCK. Both report the protocol buffers
after that as malformed, which is a statement about the dissectors, so the oracle asserts the
fields they read rather than a clean expert log. The DataTransfer packets and checksums are
checked by the raw client's own CRC32C and by both independent clients.

## Mutation-checked

Each applied alone, the named test failing on its own assertion, then reverted. For the append,
truncate, concat and deadline pass (21 mutants, every one caught): verifying an append's first
packet against the block's chunk (the committed partial bytes and the new ones) instead of its
own bytes — `append_continues_the_partial_last_chunk` gets SUCCESS for the whole-chunk CRC, and
Hadoop's `-appendToFile` and colinmarc's Client.Append both get ERROR_CHECKSUM; dropping the
partial-chunk alignment rule (the same test gets SUCCESS for the crossing packet); applying a
truncate inside a block at once (`truncate_inside_a_block_goes_through_recovery` gets true, and
`-truncate -w` prints no "Waiting for"); each of the ten concat preconditions removed in turn
(its row of `concat_preconditions_are_refused_before_the_model`; the partial target and other
directory rows of `hadoop_cli_concats` too); each of the five deadlines read from its constant
instead of its setting (its `deadline_test.rs` test waits out its 8 s); an unanswered append,
truncate or concat treated as allowed, each alone (`new_mutations_fail_closed_without_an_answer`).
Earlier: the RPC frame
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
export NETGET_GO_HDFS_APPEND=$(go env GOPATH)/bin/netget-hdfs-append
./cargo-isolated.sh test --no-default-features --test server -- server::hdfs:: --test-threads=4
```

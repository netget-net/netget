# HDFS NameNode and DataNode — Experimental

One NetGet server is a whole (one-node) HDFS: a **NameNode** speaking Hadoop IPC version 9
and ClientNamenodeProtocol on the server's port (well-known 8020), and a **DataNode** speaking
DataTransferProtocol version 28 on a second listener (`datanode_port`, 9866 by default; 0 is
OS-assigned; when the default is taken an OS-assigned port is used and logged, and every block
location names the real one). Rust owns the wire; the model owns the namespace and every
change to it. There is no NameNode–DataNode protocol: both halves share one `Namespace`.

| File | What it does |
|---|---|
| `proto.rs` | the prost modules generated from Hadoop 3.5.0's own `.proto` files (`proto/hadoop`, Apache-2.0, unmodified; `build.rs` compiles RpcHeader, IpcConnectionContext, ProtobufRpcEngine2, ClientNamenodeProtocol and datatransfer, with their imports) |
| `rpc.rs` | IPC framing shared with the client and the fuzz target: the `hrpc` header, frames read under a length bound and deadlines, varint-delimited messages, call frames, success/error/fatal responses, and the Java exception classes a refusal may name |
| `transfer.rs` | DataTransferProtocol shared likewise: op codes and headers, packets (PLEN/HLEN checked before anything else is read), CRC32C and CRC32 chunk checksums, delimited responses and acks, the block MD5 |
| `namespace.rs` | `src/server/described_tree.rs` (the tree FUSE serves) plus what HDFS adds: owner/group names, replication, block size and generation stamp per file, files open for writing with their allocated blocks, and block bytes received but not yet committed; every operation is a pure plan/apply pair |
| `namenode.rs` | one task per connection: header, optional SASL, connection context, user admission, then calls in order, each answered with its call id; reads describe what they need, changes are planned, asked about and applied under the decision gate |
| `datanode.rs` | one task per connection, ops one after another (Hadoop reuses a connection after a read): READ_BLOCK, WRITE_BLOCK (new blocks and appends), BLOCK_CHECKSUM |
| `actions.rs` | events, actions, startup parameters, metadata |
| `mod.rs` | settings, the shared `Hdfs` state, the decision gate and `ask`, spawn |

## What the model decides

- **Which users may connect** (`hdfs_connect`): SIMPLE authentication, so the user is the name
  the client asserts in its connection context. Asked once per user and remembered (allow or
  deny) for the server's life, up to 1024 users; a failed decision is not remembered. A denied
  user's connection is closed with a FATAL response naming the model's exception.
- **What each directory contains** (`hdfs_describe_directory` → `hdfs_directory`), lazily, once
  per directory, exactly as FUSE does — the tree, its bounds and its three description attempts
  are `described_tree`'s. The vocabulary is FUSE's (`kind`, `mode` as decimal, `mtime`,
  `entries`, file content as `text` / `hex` / `extents` with failing `errors`) plus `owner`,
  `group` (names, not ids), `replication` and `block_size`, checked before anything is
  committed. A file's content is cut into blocks of its block size. `hdfs_deny` makes the
  directory read as the exception's errno equivalent (AccessControlException → EACCES,
  FileNotFoundException → ENOENT, anything else EIO) for the server's life.
- **Every change**: `hdfs_mkdirs`, `hdfs_create`, `hdfs_append`, `hdfs_write` (the content of
  a completed file or append), `hdfs_truncate`, `hdfs_concat`, `hdfs_delete`, `hdfs_rename`,
  `hdfs_set_permission`, `hdfs_set_owner`, `hdfs_set_times`, `hdfs_set_replication`, each
  `hdfs_allow` or `hdfs_deny` with an exception
  from `rpc::EXCEPTIONS` (AccessControlException by default) and a message the client shows.
  What HDFS itself would refuse — FileAlreadyExistsException, FileNotFoundException,
  ParentNotDirectoryException, PathIsNotEmptyDirectoryException, a lease another client holds —
  is refused in Rust first (`decision=protocol_refusal`) and the model is not asked.

Reads, listings, stats, block locations, content summaries and every block transfer cost no
model call once the directories involved are described.

## Writes (the storage question)

A write is `create` (one decision: may this file exist), then `addBlock` per block, the
blocks streamed to the DataNode, then `complete`. The DataNode verifies every chunk's checksum
and holds each block's bytes **staged** (counted against `max_overlay_bytes`); nothing reaches
the namespace until `complete`, where the model sees the length, block count and the first
512 bytes (text, or hex) and decides (`hdfs_write`). Allowed: the bytes go into the tree's
in-memory overlay, which lasts until the server stops — the same choice FUSE, NVMe/TCP and
iSCSI make. Refused, undecided or failed: the staged bytes are discarded, the file keeps its
earlier content (empty for a new file), and `complete` fails with the exception. `hdfs dfs
-put` therefore asks three times: create of `<name>._COPYING_`, its content, and the rename.

**Append** is the same shape: `append` (one decision, `hdfs_append`: may this file grow), then
the bytes, then `complete`, where `hdfs_write` shows them with `append: true` and the `offset`
they land at. A file whose last block is partial reopens that block: `append` answers it
located with the bytes it holds, the client asks `updateBlockForPipeline` for a new generation
stamp, opens WRITE_BLOCK in `PIPELINE_SETUP_APPEND` naming the block's length
(`minBytesRcvd`) and the new stamp, and `updatePipeline` makes the file adopt the stamp
(colinmarc/hdfs skips the new stamp and runs the pipeline under the old one, which is
accepted too). Its first packet continues the partial last chunk **alone**, its CRC32C over its
own bytes only; the DataNode refuses a packet that starts inside a chunk and runs past its end,
and serves every chunk's checksum afterwards from the content, so the continued chunk's is over
the old and new bytes together. A file whose last block is full (or that is empty) reopens
nothing; the next addBlock starts the next block. While the file is open for append its
committed bytes stay readable, reported as complete blocks. Refused, undecided or failed:
the appended bytes go and the file keeps what it had. `NEW_BLOCK` (`-appendToFile -n`) after a
partial block is refused (`UnsupportedOperationException`): blocks here are a file's content
cut at its block size, so a short block in the middle of a file cannot be represented.

**Truncate** (`hdfs_truncate`) on a block boundary is done at once and answers true. Inside a
block it answers **false** and the file goes under block recovery, as Hadoop's NameNode reports
an in-place truncate: `isFileClosed` is false, `getFileInfo` still reports the old length,
block locations and reads end at the new length, a truncate to the same length answers false
again without asking, any other truncate is `AlreadyBeingCreatedException` and an append
`RecoveryInProgressException`. After `TRUNCATE_RECOVERY` (one second, a DataNode heartbeat's
worth) the next look at the namespace finishes it: the file is cut, takes the recovery's
generation stamp and closes — which is what `hdfs dfs -truncate -w` polls `getFileInfo` for.

**Concat** (`hdfs_concat`) keeps Hadoop 3.5's own checks in Rust (the target a closed file;
every source a closed, non-empty file in the target's directory, not the target, none twice,
its block size no larger than the target's) and adds this NameNode's: every file the target's
block size, and the target and every source but the last whole blocks (the same
variable-length-block limit). Then the model; then the sources' bytes are written onto the end
of the target's overlay (checked against `max_overlay_bytes` first, every source read whole
first — a described failing region cannot be moved) and the sources are removed.

## Failure

| Outcome | Client sees | `decision=` |
|---|---|---|
| allowed and applied | success | `model_answer` |
| refused by the model | its exception and message | `model_reject` |
| refused before asking | HDFS's own exception | `protocol_refusal` |
| deadline passed | IOException "could not decide in time" | `fail_closed_deadline` |
| backend failed | IOException (RetriableException when overloaded) | `fail_closed_llm_error` |
| no answer | IOException | `model_silent` |
| broken answer | IOException | `fail_closed_invalid_reply` |
| `read_only` | SafeModeException, the model not asked | `read_only` |

The client is never told why the backend failed. `decision_timeout_secs` (default 60) covers
the wait for the gate and the model call.

## The decision gate

One model question at a time per server (`Hdfs::gate`): a change is planned, asked about and
applied while it is held, so the plan the model approved is the one applied; a directory is
described once however many calls wanted it. Reads take the gate only to describe.

## Calls

Served: getServerDefaults, getFileInfo, getFileLinkInfo, getLocatedFileInfo, getListing
(pages of 1000 after `startAfter`, with locations on request), getBlockLocations, mkdirs,
create (APPEND refused), addBlock (a client that excluded the one DataNode gets Hadoop's own
"could only be written to 0 of the 1 minReplication nodes"), abandonBlock, complete,
updateBlockForPipeline (the block located again, generation stamp unchanged — colinmarc/hdfs
calls it after every block), updatePipeline (accepted only for the same block and node),
delete, rename (the old false-returning semantics, a directory destination receiving the
source), rename2, setPermission, setOwner, setTimes, setReplication, renewLease, recoverLease,
isFileClosed, fsync, getFsStats (capacity is the overlay bound), getContentSummary and
getQuotaUsage (describing what they walk, at most 256 directories), getPreferredBlockSize,
getLinkTarget, checkAccess (mode bits: owner, a group named after the user, others; the
`owner` parameter is superuser), getStoragePolicy/getStoragePolicies (HOT),
getErasureCodingPolicy (none), getDataEncryptionKey (none), getDatanodeReport, getEnclosingRoot,
getHAServiceState (ACTIVE), msync, append (flags APPEND and NEW_BLOCK), truncate, concat,
getAdditionalDatanode (the block located on the one DataNode it already has; a client with a
replace-datanode policy finds no new node and goes on or fails as its policy says). Unknown
methods: RpcNoSuchMethodException, ERROR_NO_SUCH_METHOD. createSymlink:
UnsupportedOperationException. updateBlockForPipeline offers a new generation stamp and
updatePipeline adopts it, for the same block on the same node only.

## DataNode

- **READ_BLOCK**: chunk-aligned packets of up to 64 KiB with CRC32C in 512-byte chunks (none
  when the client asks for no checksums), from the chunk holding `offset` to the chunk holding
  the last byte asked for, then the empty last packet; the client's read status is read and the
  connection kept for the next op. A described failing region ends the transfer mid-block, as a
  DataNode does on a disk error.
- **WRITE_BLOCK**: PIPELINE_SETUP_CREATE for a block allocated since the file was opened,
  PIPELINE_SETUP_APPEND for the partial last block an append reopened (its `minBytesRcvd` the
  bytes it holds, its `latestGenerationStamp` the file's or the one updateBlockForPipeline
  offered); no recovery stages, no downstream targets (this node is the whole pipeline), CRC32C
  or CRC32 chunks of 16 B–64 KiB. Only the newest block of a file the writing client holds
  open, not yet received. A packet may not start before the bytes an append continues, and one
  that starts inside a chunk must end by that chunk's end. Each packet is verified chunk by chunk and acked (`reply` and Hadoop 3's
  `flag`); a bad chunk is ERROR_CHECKSUM and the block is dropped. Heartbeats (seqno -1) are
  acked. Acks are written before the next packet is read, so at most one is outstanding here.
- **BLOCK_CHECKSUM**: MD5 of the block's CRC32C chunk checksums (MD5CRC; COMPOSITE_CRC refused).
- Anything else: ERROR_UNSUPPORTED. A version other than 28: ERROR_INVALID naming both.

Blocks are not stored: block `i` of inode `ino` has id `ino << 16 | i`, and its bytes are read
from the tree when asked.

## Bounds

RPC frames of 1 MiB (`rpc::MAX_REQUEST_FRAME`, refused FATAL from the length alone). The
connection deadlines are startup parameters whose defaults are the constants in `mod.rs`: the
connection header and context, and a DataNode's first op, within `header_timeout_secs` (30);
the rest of a frame, op or packet within `frame_timeout_secs` (60) of its first byte, which
also bounds writing a response; `idle_timeout_secs` (300) between calls;
`op_idle_timeout_secs` (60) between DataNode ops; `packet_timeout_secs` (120) between packets
of a write — each 1 to 3600, and each tested with a stalled peer in `deadline_test.rs`.
Packets of 1 MiB of data and a 1 KiB header; 1000 entries per listing page; block sizes of
64 KiB to 1 GiB in multiples of 512 and 16384 blocks per file; 256 files open for writing or
under truncate recovery; 256 sources per concat; the overlay (default 64 MiB) for written,
appended and concatenated pages and staged blocks; 256 connections per listener; everything
`described_tree` bounds. Protocol buffers are decoded by prost, whose decoder stops at 100
levels of nesting.

## Not implemented

Kerberos, delegation and block tokens, SASL beyond SIMPLE, data transfer encryption; symlink
creation (Hadoop 3 disables symlinks in its client unless `FileSystem.enableSymlinks()` is
called, which only tests do, and `hdfs dfs` has no command that creates one — no peer could
drive it), snapshots, ACLs, extended attributes, quotas, encryption zones, erasure coding,
caching, pipeline recovery onto another node or block (updatePipeline accepts the same block on
the same node only), variable-length blocks (append NEW_BLOCK after a partial block, concat of
partial blocks), short-circuit reads, ClientDatanodeProtocol (ipcPort 0), replication (one
DataNode; replication is reported, not performed). Reads are not permission-checked: the model
decides changes, and who may connect.

## Evidence and maturity

Experimental. Two independent clients pass on macOS: Apache Hadoop 3.5.0's `hdfs dfs` (Java)
and colinmarc/hdfs v2.4.0 (Go, its own RPC and data transfer code). Both drive append and
truncate; only Hadoop drives concat (colinmarc/hdfs has no concat at all) and
getAdditionalDatanode. colinmarc's `hdfs` command has no append subcommand, so its library's
`Client.Append` is reached through `tests/server/hdfs/goappend`, a driver with no protocol code
of its own. In CI they run only in the `hdfs` pair job. tshark's `hdfs` and `hdfsdata`
dissectors predate Hadoop 2's protocol buffers: on this traffic they read the `hrpc` header and
the op header, which the oracle asserts, and flag the protocol buffers as malformed. See
`tests/server/hdfs/AGENTS.md`. The fuzz target is `fuzz/fuzz_targets/hdfs_wire.rs`.

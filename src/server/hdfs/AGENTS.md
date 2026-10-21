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
| `datanode.rs` | one task per connection, ops one after another (Hadoop reuses a connection after a read): READ_BLOCK, WRITE_BLOCK, BLOCK_CHECKSUM |
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
- **Every change**: `hdfs_mkdirs`, `hdfs_create`, `hdfs_write` (the content of a completed
  file), `hdfs_delete`, `hdfs_rename`, `hdfs_set_permission`, `hdfs_set_owner`,
  `hdfs_set_times`, `hdfs_set_replication`, each `hdfs_allow` or `hdfs_deny` with an exception
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
getHAServiceState (ACTIVE), msync. Unknown methods: RpcNoSuchMethodException, ERROR_NO_SUCH_METHOD.
append, truncate, concat and createSymlink: UnsupportedOperationException.

## DataNode

- **READ_BLOCK**: chunk-aligned packets of up to 64 KiB with CRC32C in 512-byte chunks (none
  when the client asks for no checksums), from the chunk holding `offset` to the chunk holding
  the last byte asked for, then the empty last packet; the client's read status is read and the
  connection kept for the next op. A described failing region ends the transfer mid-block, as a
  DataNode does on a disk error.
- **WRITE_BLOCK**: PIPELINE_SETUP_CREATE only (no append, no recovery stages), no downstream
  targets (this node is the whole pipeline), CRC32C or CRC32 chunks of 16 B–64 KiB. Only the
  newest block of a file the writing client holds open, not yet received, with the file's
  generation stamp. Each packet is verified chunk by chunk and acked (`reply` and Hadoop 3's
  `flag`); a bad chunk is ERROR_CHECKSUM and the block is dropped. Heartbeats (seqno -1) are
  acked. Acks are written before the next packet is read, so at most one is outstanding here.
- **BLOCK_CHECKSUM**: MD5 of the block's CRC32C chunk checksums (MD5CRC; COMPOSITE_CRC refused).
- Anything else: ERROR_UNSUPPORTED. A version other than 28: ERROR_INVALID naming both.

Blocks are not stored: block `i` of inode `ino` has id `ino << 16 | i`, and its bytes are read
from the tree when asked.

## Bounds

RPC frames of 1 MiB (`rpc::MAX_REQUEST_FRAME`, refused FATAL from the length alone); the
connection header within 30 s, a frame's rest within 60 s of its first byte, 300 s idle; the
first op within 30 s, 60 s between ops, 120 s between packets of a write; packets of 1 MiB of
data and a 1 KiB header; 1000 entries per listing page; block sizes of 64 KiB to 1 GiB in
multiples of 512 and 16384 blocks per file; 256 files open for writing; the overlay (default
64 MiB) for written pages and staged blocks; 256 connections per listener; everything
`described_tree` bounds. Protocol buffers are decoded by prost, whose decoder stops at 100
levels of nesting.

## Not implemented

Kerberos, delegation and block tokens, SASL beyond SIMPLE, data transfer encryption; append,
truncate, concat, symlink creation, snapshots, ACLs, extended attributes, quotas, encryption
zones, erasure coding, caching, pipeline recovery, short-circuit reads, ClientDatanodeProtocol
(ipcPort 0), replication (one DataNode; replication is reported, not performed). Reads are not
permission-checked: the model decides changes, and who may connect.

## Evidence and maturity

Experimental. Two independent clients pass on macOS: Apache Hadoop 3.5.0's `hdfs dfs` (Java)
and colinmarc/hdfs v2.4.0 (Go, its own RPC and data transfer code). In CI they run only in the
`hdfs` pair job, which had not run when this landed. tshark's `hdfs` and `hdfsdata`
dissectors predate Hadoop 2's protocol buffers: on this traffic they read the `hrpc` header and
the op header, which the oracle asserts, and flag the protocol buffers as malformed. See
`tests/server/hdfs/AGENTS.md`. The fuzz target is `fuzz/fuzz_targets/hdfs_wire.rs`.

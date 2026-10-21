# HDFS client — Experimental

`namenode.rs` is a Hadoop IPC connection (the `hrpc` header with SIMPLE authentication and no
SASL, the connection context naming the user, calls one at a time matched by call id);
`blocks.rs` reads and writes blocks with a DataNode; `mod.rs` turns the model's actions into
calls and raises each result; `actions.rs` holds the vocabulary. The framing is the server's
(`src/server/hdfs/rpc.rs`, `src/server/hdfs/transfer.rs`), so the client is Unix-only too.

**Lifecycle.** `connect()` opens the NameNode connection as the `user` startup parameter
(default `netget`) and calls getServerDefaults; a refusal fails the start. It raises
`hdfs_connected` with the server's defaults. A connection that fails or is closed with a fatal
response is reopened before the next action.

| Action | Calls | Event |
|---|---|---|
| `hdfs_list` | getListing (one page; `start_after` for the next) | `hdfs_listing` (at most 200 entries, `remaining`) |
| `hdfs_stat` | getFileInfo | `hdfs_file_status` (`exists` false when absent) |
| `hdfs_read` | getBlockLocations, then READ_BLOCK on each block's first location | `hdfs_read_result` (at most 64 KiB; text when it is text, hex otherwise or when asked) |
| `hdfs_mkdir` | mkdirs | `hdfs_mutation_result` |
| `hdfs_write` | create, addBlock and WRITE_BLOCK per block, complete (retried while it answers false) | `hdfs_write_result` (at most 1 MiB) |
| `hdfs_delete` | delete | `hdfs_mutation_result` (`result` false when nothing was there) |
| `hdfs_rename` | rename2 | `hdfs_mutation_result` |
| `hdfs_set_permission` | setPermission | `hdfs_mutation_result` |
| `disconnect` | — | — |

Any exception becomes `hdfs_error` with Hadoop's `exception_class` and message; a transport
failure has an empty class and says what failed.

**Reads** check that the DataNode starts at or just before the offset (a chunk boundary), that
packets are contiguous, and every chunk against its CRC32C or CRC32 before believing the bytes;
then CHECKSUM_OK. **Writes** use CRC32C in 512-byte chunks and 64 KiB packets, at most eight
unacknowledged, through the pipeline the NameNode names (`targets` its later locations); every
ack must carry the next sequence number and SUCCESS for every node (`flag` when present, else
`reply`). The last, empty packet goes once every data packet is acknowledged. No append, no
hflush, no pipeline recovery.

**Bounds.** Response frames of 16 MiB, packets of 1 MiB, 1024 packets per read, 60 s per call
and per DataNode step, 16 follow-ups per handler chain (a whole list, stat, read, write, rename,
chmod and delete session is twelve). A failed model call sends nothing.

**Evidence.** `tests/client/hdfs/real_server_test.rs`, against a real single-node HDFS from
Apache Hadoop 3.5.0, in the `hdfs` pair job. Experimental: one independent peer, and the job
had not run in CI when this landed.

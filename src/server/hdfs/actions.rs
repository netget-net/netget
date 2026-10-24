//! What the model decides for an HDFS NameNode and DataNode: which users may connect (asked
//! once per user), what each directory contains (asked once, the first time a call looks inside
//! it), and whether each change a client asks for may happen. Every read, listing, stat, block
//! location and block transfer after that is answered from the description at no model cost.
use super::namespace;
use super::rpc;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::server::described_tree;
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const DIRECTORY: &str = "hdfs_directory";
pub const ALLOW: &str = "hdfs_allow";
pub const DENY: &str = "hdfs_deny";

/// The longest message a refusal may carry to the client.
pub const MAX_DENY_MESSAGE: usize = 1024;

pub fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required,
    }
}

fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
) -> ActionDefinition {
    let log = match name {
        DIRECTORY => LogTemplate::new().with_info("-> HDFS directory {preview(entries,120)}"),
        DENY => LogTemplate::new().with_info("-> HDFS deny {exception}"),
        _ => LogTemplate::new().with_info(format!("-> {name}")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log),
    }
}

pub fn directory_action() -> ActionDefinition {
    action(
        DIRECTORY,
        "Describe the directory's entries. NetGet answers every getFileInfo, getListing, \
         getBlockLocations and block read in it from this description without asking again; \
         a file's content is cut into blocks of its block_size and served by the DataNode. A \
         file's content is text (UTF-8), hex, or extents over its size ({offset, text} | \
         {offset, hex} | {offset, length, fill: 0-255}; bytes no extent covers read as \
         zeroes); errors are byte ranges whose block reads fail. A subdirectory may carry its \
         own entries (described now) or none (asked about when first opened).",
        vec![p(
            "entries",
            "array",
            "[{name, kind: file|dir|symlink, mode (decimal permission bits: 420 is 0644, 493 is \
             0755), owner, group (names; default the owner and group startup parameters), \
             mtime/atime (Unix seconds); file: text | hex | extents with size, size (default: \
             the text's length), replication (1-512), block_size (a multiple of 512 from 65536 \
             to 1073741824; default the block_size startup parameter), errors ([{offset, \
             length}]); dir: entries (optional, nested the same way); symlink: target}], at \
             most 4096 per directory and 16384 per answer, names 1-255 bytes without '/' or \
             ':', 64 directories deep, 16 MiB of text and hex over the namespace, files up to \
             1 GiB and 16384 blocks",
            true,
        )],
        json!({"type": DIRECTORY, "entries": [
            {"name": "README.txt", "kind": "file", "text": "hello from netget\n", "mode": 420, "owner": "alice", "group": "analysts"},
            {"name": "events.log", "kind": "file", "size": 196608, "block_size": 65536,
             "extents": [{"offset": 0, "text": "2026-10-20 started\n"}, {"offset": 65536, "length": 65536, "fill": 65}]},
            {"name": "user", "kind": "dir", "entries": [{"name": "alice", "kind": "dir", "owner": "alice"}]},
            {"name": "tmp", "kind": "dir", "mode": 1023}
        ]}),
    )
}

pub fn allow_action() -> ActionDefinition {
    action(
        ALLOW,
        "Let it happen: the user connects, or the change is applied to the namespace's \
         in-memory overlay (which lasts until the server stops) and the call succeeds.",
        vec![],
        json!({"type": ALLOW}),
    )
}

pub fn deny_action() -> ActionDefinition {
    action(
        DENY,
        "Refuse: the call fails with this Java exception and nothing changes. For a connection, \
         the client's connection is closed with it; for a directory description, every call \
         inside that directory fails the same way.",
        vec![
            p(
                "exception",
                "string",
                &format!(
                    "The exception: {} (default AccessControlException)",
                    rpc::exception_names()
                ),
                false,
            ),
            p(
                "message",
                "string",
                "The exception's message, shown to the user (at most 1024 bytes)",
                false,
            ),
        ],
        json!({"type": DENY, "exception": "AccessControlException", "message": "Permission denied: user=bob, access=WRITE, inode=\"/data\""}),
    )
}

fn who() -> Vec<Parameter> {
    vec![
        p(
            "user",
            "string",
            "The effective user the client connected as",
            true,
        ),
        p(
            "client_address",
            "string",
            "The address the client connected from",
            true,
        ),
    ]
}

fn path() -> Parameter {
    p("path", "string", "The absolute path in HDFS", true)
}

fn change_event(
    id: &'static str,
    description: &str,
    mut parameters: Vec<Parameter>,
    log: &str,
) -> EventType {
    parameters.extend(who());
    EventType::new(id, description, allow_action().example)
        .with_parameters(parameters)
        .with_actions(vec![allow_action(), deny_action()])
        .with_log_template(LogTemplate::new().with_info(log.to_string()))
}

pub static CONNECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hdfs_connect",
        "A client connected to the NameNode as a user nobody has decided about yet (SIMPLE \
         authentication: the user is the name the client asserts). Answer hdfs_allow to let \
         that user in for the life of the server, or hdfs_deny to refuse every connection \
         that asserts it.",
        allow_action().example,
    )
    .with_parameters(vec![
        p(
            "user",
            "string",
            "The effective user the client asserts",
            true,
        ),
        p(
            "real_user",
            "string",
            "The real user, when a proxy user acts for the effective user",
            false,
        ),
        p(
            "client_address",
            "string",
            "Where the client connected from",
            true,
        ),
        p(
            "protocol",
            "string",
            "The protocol the client named (org.apache.hadoop.hdfs.protocol.ClientProtocol)",
            true,
        ),
        p(
            "auth",
            "string",
            "none (SIMPLE without SASL) or sasl-simple",
            true,
        ),
    ])
    .with_actions(vec![allow_action(), deny_action()])
    .with_log_template(LogTemplate::new().with_info("HDFS connect {user} from {client_address}"))
});

pub static DESCRIBE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut parameters = vec![
        path(),
        p(
            "depth",
            "number",
            "Directories between it and the root (the root is 0)",
            true,
        ),
        p(
            "method",
            "string",
            "The NameNode call that looked inside (getFileInfo, getListing, mkdirs, create, …)",
            true,
        ),
    ];
    parameters.extend(who());
    EventType::new(
        "hdfs_describe_directory",
        "A call looked inside a directory nobody has described yet. Answer hdfs_directory with \
         its entries (asked once per directory for the life of the server), or hdfs_deny.",
        directory_action().example,
    )
    .with_parameters(parameters)
    .with_actions(vec![directory_action(), deny_action()])
    .with_log_template(LogTemplate::new().with_info("HDFS describe {path} ({method})"))
});

pub static MKDIRS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "hdfs_mkdirs",
        "A client makes directories (mkdirs). Allow it (they appear, empty) or deny it.",
        vec![
            path(),
            p(
                "creates",
                "array",
                "Every directory that would be made, parents first",
                true,
            ),
            p(
                "mode",
                "number",
                "The permission bits asked for (decimal)",
                true,
            ),
        ],
        "HDFS mkdirs {path}",
    )
});

pub static CREATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "hdfs_create",
        "A client creates a file to write (create). Allow it (an empty file appears, open for \
         this client; its content is decided again by hdfs_write when it completes) or deny it.",
        vec![
            path(),
            p(
                "overwrite",
                "boolean",
                "Whether the client asked to overwrite an existing file",
                true,
            ),
            p(
                "replaces",
                "boolean",
                "Whether an existing file at path would be replaced",
                true,
            ),
            p(
                "creates_parents",
                "array",
                "Directories that would be made on the way, parents first",
                true,
            ),
            p(
                "mode",
                "number",
                "The permission bits asked for (decimal)",
                true,
            ),
            p("replication", "number", "The replication asked for", true),
            p(
                "block_size",
                "number",
                "The block size asked for, bytes",
                true,
            ),
            p(
                "client_name",
                "string",
                "The writing client's name (its lease holder id)",
                true,
            ),
        ],
        "HDFS create {path}",
    )
});

pub static WRITE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "hdfs_write",
        "A client finished writing a file (complete): the DataNode received its blocks and \
         verified their checksums. Allow it (the bytes become the file's content, or are added \
         to its end for an append, in the overlay) or deny it (the bytes are discarded, the \
         file keeps its earlier content and the client's complete fails with the exception).",
        vec![
            path(),
            p(
                "length",
                "number",
                "Bytes the client wrote to the file",
                true,
            ),
            p(
                "offset",
                "number",
                "Where they go in the file: 0 for a new file, its length before an append",
                true,
            ),
            p(
                "append",
                "boolean",
                "Whether the bytes are appended to an existing file",
                true,
            ),
            p(
                "blocks",
                "number",
                "How many blocks the bytes were written in",
                true,
            ),
            p(
                "data",
                "string",
                "The first bytes, in the encoding named beside it",
                true,
            ),
            p(
                "encoding",
                "string",
                "utf8 when the data is text, hex otherwise",
                true,
            ),
            p(
                "data_truncated",
                "boolean",
                "Whether data shows only the first bytes",
                true,
            ),
            p("client_name", "string", "The writing client's name", true),
        ],
        "HDFS write {path} length={length}",
    )
});

pub static APPEND_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "hdfs_append",
        "A client opens an existing file to add bytes to its end (append, hdfs dfs \
         -appendToFile). Allow it (the file opens for this client; what it writes is decided \
         again by hdfs_write when it completes) or deny it.",
        vec![
            path(),
            p("length", "number", "The file's length now, bytes", true),
            p("block_size", "number", "The file's block size, bytes", true),
            p(
                "last_block_partial",
                "boolean",
                "Whether the last block is partial (the append continues it)",
                true,
            ),
            p(
                "new_block",
                "boolean",
                "Whether the client asked for the bytes to start a new block",
                true,
            ),
            p(
                "client_name",
                "string",
                "The writing client's name (its lease holder id)",
                true,
            ),
        ],
        "HDFS append {path}",
    )
});

pub static TRUNCATE_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        change_event(
        "hdfs_truncate",
        "A client cuts a file to a shorter length (truncate, hdfs dfs -truncate). Allow it (the \
         bytes after length go; a cut inside a block finishes after a short block recovery, \
         during which the file stays open) or deny it.",
        vec![
            path(),
            p("length", "number", "The new length, bytes", true),
            p("length_before", "number", "The file's length now, bytes", true),
            p("block_size", "number", "The file's block size, bytes", true),
            p(
                "on_block_boundary",
                "boolean",
                "Whether the new length is a whole number of blocks (done at once)",
                true,
            ),
            p("client_name", "string", "The truncating client's name", true),
        ],
        "HDFS truncate {path} to {length}",
    )
    });

pub static CONCAT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "hdfs_concat",
        "A client joins files onto the end of path (concat, hdfs dfs -concat): the sources' \
         blocks move onto path, in order, and the sources are removed. Allow or deny.",
        vec![
            path(),
            p(
                "sources",
                "array",
                "The files whose bytes are added, in order (each is removed)",
                true,
            ),
            p("length_before", "number", "path's length now, bytes", true),
            p("length", "number", "path's length after, bytes", true),
            p(
                "block_size",
                "number",
                "The block size they share, bytes",
                true,
            ),
        ],
        "HDFS concat {path} <- {sources}",
    )
});

pub static DELETE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "hdfs_delete",
        "A client deletes a file or directory (delete). Allow or deny.",
        vec![
            path(),
            p("kind", "string", "file, dir or symlink", true),
            p(
                "recursive",
                "boolean",
                "Whether everything below a directory goes with it",
                true,
            ),
        ],
        "HDFS delete {path}",
    )
});

pub static RENAME_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "hdfs_rename",
        "A client moves or renames an entry (rename, rename2). Allow or deny.",
        vec![
            path(),
            p("destination", "string", "The path it moves to", true),
            p("kind", "string", "file, dir or symlink", true),
            p(
                "replaces",
                "boolean",
                "Whether something at destination is replaced",
                true,
            ),
        ],
        "HDFS rename {path} -> {destination}",
    )
});

pub static SET_PERMISSION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "hdfs_set_permission",
        "A client changes an entry's permission bits (setPermission, chmod). Allow or deny.",
        vec![
            path(),
            p("mode", "number", "The new permission bits (decimal)", true),
            p("mode_before", "number", "The bits before (decimal)", true),
        ],
        "HDFS chmod {path} {mode}",
    )
});

pub static SET_OWNER_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "hdfs_set_owner",
        "A client changes an entry's owner or group (setOwner, chown, chgrp). Only the fields \
         present change. Allow or deny.",
        vec![
            path(),
            p(
                "owner",
                "string",
                "The user name to become the owner",
                false,
            ),
            p(
                "group",
                "string",
                "The group name to become the group",
                false,
            ),
            p("owner_before", "string", "The owner before", true),
            p("group_before", "string", "The group before", true),
        ],
        "HDFS chown {path}",
    )
});

pub static SET_TIMES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "hdfs_set_times",
        "A client changes an entry's times (setTimes, touch). Only the fields present change. \
         Allow or deny.",
        vec![
            path(),
            p(
                "mtime",
                "number",
                "The new modification time, Unix milliseconds",
                false,
            ),
            p(
                "atime",
                "number",
                "The new access time, Unix milliseconds",
                false,
            ),
        ],
        "HDFS setTimes {path}",
    )
});

pub static SET_REPLICATION_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        change_event(
        "hdfs_set_replication",
        "A client changes a file's replication (setReplication, setrep). This NameNode has one \
         DataNode, so it changes the number reported, not the copies kept. Allow or deny.",
        vec![
            path(),
            p("replication", "number", "The new replication", true),
            p("replication_before", "number", "The replication before", true),
        ],
        "HDFS setReplication {path} {replication}",
    )
    });

/// The Java class and message of an `hdfs_deny` answer.
pub fn denial(v: &Value) -> (&'static str, String) {
    let class = v["exception"]
        .as_str()
        .and_then(rpc::exception_class)
        .unwrap_or(rpc::class::ACCESS_CONTROL);
    let message = v["message"]
        .as_str()
        .map(crate::utils::sanitize::line_field)
        .filter(|m| !m.trim().is_empty())
        .unwrap_or_else(|| "Permission denied".into());
    (class, message)
}

/// Check an answer's shape: what the executor accepts before the server looks at it in place.
pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        DIRECTORY => {
            namespace::check_description(v)?;
        }
        ALLOW => {}
        DENY => {
            match &v["exception"] {
                Value::Null => {}
                Value::String(e) => ensure!(
                    rpc::exception_class(e).is_some(),
                    "exception is one of {}",
                    rpc::exception_names()
                ),
                _ => bail!("exception is a name"),
            }
            match &v["message"] {
                Value::Null => {}
                Value::String(m) => ensure!(
                    m.len() <= MAX_DENY_MESSAGE,
                    "message is at most {MAX_DENY_MESSAGE} bytes"
                ),
                _ => bail!("message is text"),
            }
        }
        other => bail!("Unknown HDFS action {other:?}"),
    }
    Ok(())
}

#[derive(Default, Clone)]
pub struct HdfsProtocol;
impl HdfsProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn number_param(
    name: &str,
    description: &str,
    example: Value,
    default: Option<Value>,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: "number".into(),
        description: description.into(),
        required: false,
        example,
        default,
    }
}

impl Protocol for HdfsProtocol {
    fn protocol_name(&self) -> &'static str {
        "HDFS"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HDFS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "hdfs",
            "namenode",
            "datanode",
            "hadoop distributed file system",
            "hdfs dfs",
        ]
    }
    fn description(&self) -> &'static str {
        "HDFS NameNode and DataNode (Hadoop IPC on 8020, DataTransferProtocol on 9866): the \
         model decides which users may connect, what each directory contains and whether each \
         change may happen; NetGet serves the RPCs, block locations and checksummed block \
         reads and writes from that description"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![directory_action(), allow_action(), deny_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECT_EVENT.clone(),
            DESCRIBE_EVENT.clone(),
            MKDIRS_EVENT.clone(),
            CREATE_EVENT.clone(),
            WRITE_EVENT.clone(),
            APPEND_EVENT.clone(),
            TRUNCATE_EVENT.clone(),
            CONCAT_EVENT.clone(),
            DELETE_EVENT.clone(),
            RENAME_EVENT.clone(),
            SET_PERMISSION_EVENT.clone(),
            SET_OWNER_EVENT.clone(),
            SET_TIMES_EVENT.clone(),
            SET_REPLICATION_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            number_param(
                "datanode_port",
                "The DataNode's data transfer port (0: an OS-assigned port). When the default is \
                 taken, an OS-assigned port is used and the NameNode reports it in every block \
                 location; a port named here is never replaced",
                json!(9866),
                Some(json!(super::DEFAULT_DATANODE_PORT)),
            ),
            number_param(
                "block_size",
                "The block size of described files that name none, and what getServerDefaults \
                 reports (a multiple of 512 from 65536 to 1073741824)",
                json!(134217728),
                Some(json!(namespace::DEFAULT_BLOCK_SIZE)),
            ),
            number_param(
                "replication",
                "The replication described files report when they name none (1-512; there is one \
                 DataNode whatever it says)",
                json!(1),
                Some(json!(super::DEFAULT_REPLICATION)),
            ),
            ParameterDefinition {
                name: "owner".into(),
                type_hint: "string".into(),
                description: "The owner of entries that name none, and the superuser \
                              checkAccess always allows"
                    .into(),
                required: false,
                example: json!("hdfs"),
                default: Some(json!(super::DEFAULT_OWNER)),
            },
            ParameterDefinition {
                name: "group".into(),
                type_hint: "string".into(),
                description: "The group of entries that name none".into(),
                required: false,
                example: json!("supergroup"),
                default: Some(json!(super::DEFAULT_GROUP)),
            },
            ParameterDefinition {
                name: "read_only".into(),
                type_hint: "boolean".into(),
                description: "Refuse every change with SafeModeException without asking the \
                              model, as a NameNode in safe mode does"
                    .into(),
                required: false,
                example: json!(false),
                default: None,
            },
            number_param(
                "decision_timeout_secs",
                "How long a call waits for a description or a decision before it fails closed \
                 with an exception (1-600)",
                json!(30),
                Some(json!(super::DEFAULT_DECISION_TIMEOUT.as_secs())),
            ),
            number_param(
                "header_timeout_secs",
                "Seconds a NameNode connection has to send its connection header (and its \
                 connection context), and a DataNode connection its first op, before it is \
                 closed (1-3600)",
                json!(30),
                Some(json!(super::HEADER_DEADLINE.as_secs())),
            ),
            number_param(
                "frame_timeout_secs",
                "Seconds the rest of an RPC frame, op or packet has once its first byte arrived, \
                 and a client has to take a response, before the connection is closed (1-3600)",
                json!(60),
                Some(json!(super::FRAME_DEADLINE.as_secs())),
            ),
            number_param(
                "idle_timeout_secs",
                "Seconds a NameNode connection may go without a call before it is closed \
                 (1-3600)",
                json!(300),
                Some(json!(super::IDLE_TIMEOUT.as_secs())),
            ),
            number_param(
                "op_idle_timeout_secs",
                "Seconds a DataNode connection kept after an op may wait for the next op before \
                 it is closed (1-3600)",
                json!(60),
                Some(json!(super::OP_IDLE.as_secs())),
            ),
            number_param(
                "packet_timeout_secs",
                "Seconds a block write may go without a packet before the block is dropped and \
                 the connection closed (1-3600; Hadoop's client sends a heartbeat every 30)",
                json!(120),
                Some(json!(super::PACKET_IDLE.as_secs())),
            ),
            number_param(
                "max_overlay_bytes",
                "Bytes of accepted writes (whole 4 KiB pages) the namespace holds in memory, \
                 and blocks received but not completed; past it a write fails with \
                 DSQuotaExceededException (up to 1 GiB)",
                json!(16777216),
                Some(json!(described_tree::DEFAULT_MAX_OVERLAY_BYTES)),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(8020)
            .implementation("Hand-written NameNode and DataNode over Hadoop 3.5.0's own .proto files (proto/hadoop, prost): Hadoop IPC version 9 (hrpc connection header, SIMPLE authentication with or without SASL negotiation, IpcConnectionContextProto, RpcRequestHeaderProto/RequestHeaderProto calls and RpcResponseHeaderProto success, error and fatal responses with Java exception classes) and ClientNamenodeProtocol (getServerDefaults, getFileInfo, getFileLinkInfo, getListing with startAfter pages, getBlockLocations, getLocatedFileInfo, mkdirs, create, addBlock, abandonBlock, complete, delete, rename, rename2, setPermission, setOwner, setTimes, setReplication, renewLease, recoverLease, isFileClosed, fsync, getFsStats, getContentSummary, getQuotaUsage, getPreferredBlockSize, getLinkTarget, checkAccess, getStoragePolicy, getStoragePolicies, getErasureCodingPolicy, getDataEncryptionKey, getDatanodeReport, getEnclosingRoot, getHAServiceState, msync, append, truncate, concat, updateBlockForPipeline, updatePipeline, getAdditionalDatanode) in rpc.rs and namenode.rs; DataTransferProtocol version 28 (READ_BLOCK with chunk-aligned packets and CRC32C, WRITE_BLOCK as a pipeline of one in PIPELINE_SETUP_CREATE or PIPELINE_SETUP_APPEND with checksum verification and packet acks, an append's partial last chunk continued in a packet of its own, BLOCK_CHECKSUM as MD5 of the chunk CRCs) in transfer.rs and datanode.rs; the namespace is src/server/described_tree.rs (FUSE's) with HDFS's owners, block sizes, leases and staged blocks in namespace.rs")
            .llm_control("Which effective users may connect (asked once per user); what each directory contains - names, kinds, modes, owners and groups, times, file content as text/hex/extents with failing regions, replication and block size - asked once per directory when a call first looks inside it; and every change - mkdirs, create, append, the content of a completed write or append, truncate, concat, delete, rename, setPermission, setOwner, setTimes, setReplication - allowed into the in-memory overlay or refused with the Java exception the model names")
            .e2e_testing("tests/server/hdfs: the Apache Hadoop 3.5.0 hdfs dfs CLI (Java: ls, stat, cat, get, put, mkdir, rm, mv, chmod, du, test, checksum in hadoop_cli_test.rs; appendToFile with and without -n, truncate with and without -w, concat, cp in hadoop_cli_mutation_test.rs) and colinmarc/hdfs v2.4.0's Go client (its own RPC and data transfer code: ls, cat, put, mkdir, rm, mv, checksum, truncate, and its library's Client.Append through a driver that adds no protocol code) in go_client_test.rs, each counting the RPC methods and DataNode ops it sent against the ones implemented; a raw client written from the wire format for every bound, call-id correlation, checksum verification and the fail-closed paths, with the pcap oracle (tshark's hdfs and hdfsdata dissectors, which predate Hadoop 2's protocol buffers and read only the framing) in wire_test.rs, the append pipeline, truncate recovery and concat's preconditions in mutation_wire_test.rs, and every connection deadline in deadline_test.rs; in the hdfs pair job")
            .notes("Experimental: two independent clients (Hadoop 3.5.0's Java hdfs CLI and colinmarc/hdfs v2.4.0 in Go) pass on macOS; in CI they run only in the hdfs pair job, which had not run when this landed. One NameNode, one DataNode, replication reported but never performed. SIMPLE authentication only: Kerberos, delegation tokens, block tokens and data transfer encryption are not built (a SASL client offered anything but SIMPLE is refused). append reopens a partial last block (PIPELINE_SETUP_APPEND under the generation stamp updateBlockForPipeline offers and updatePipeline adopts) and its bytes are decided again at complete; append with NEW_BLOCK after a partial block is refused, because blocks here are a file's content cut at its block size and a short block mid-file cannot be represented. truncate on a block boundary is immediate; inside a block it answers false and the file stays under recovery (open, old length reported, readable to the new length) for one second, as a NameNode reports in-place block recovery. concat keeps Hadoop's own checks and adds one block size and whole blocks up to the last source. getAdditionalDatanode answers the one DataNode. Not built: symlink creation, snapshots, ACLs, extended attributes, quotas, encryption zones, erasure coding, caching, pipeline recovery onto another node or block, short-circuit reads. Reads are not permission-checked; every change is the model's decision. A description, decision or model failure past decision_timeout_secs is an IOException (RetriableException when the backend is overloaded); a model refusal is its exception. Written bytes are held per block as they arrive and committed only when complete is allowed. Bounds: RPC frames of 1 MiB, the connection header within header_timeout_secs (30), a frame's rest within frame_timeout_secs (60) of its first byte, idle_timeout_secs (300) between calls, op_idle_timeout_secs (60) between DataNode ops and packet_timeout_secs (120) between a write's packets, each tested with a short value; 1000 entries per listing page; packets of 1 MiB of data and 1 KiB of header, chunks of 16 B to 64 KiB, CRC32C or CRC32; acks written before the next packet is read; 16384 blocks per file and block sizes of 64 KiB to 1 GiB; 256 files open for writing or under truncate recovery; 256 sources per concat; the overlay (default 64 MiB) for written, appended and concatenated bytes; 256 connections per listener; three description attempts per directory.")
            .answers_on_failure()
            .request_only("The NameNode only answers calls and the DataNode only answers ops and the packets of a write: neither sends anything a client did not ask for")
            .max_inbound_bytes(rpc::MAX_REQUEST_FRAME)
            .history(HistoryMode::Last(SESSION_HISTORY_ENTRIES))
            .batching(BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "HDFS NameNode on port 8020 with /data holding a CSV and /user/alice empty; let alice write under her home and nowhere else"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_server", "base_stack": "hdfs", "port": 8020,
            "instruction": "The root holds data/ (sales.csv: 'region,total\\nnorth,10\\n') and user/alice/. Users alice and hdfs may connect. Allow alice to create, write, rename and delete under /user/alice; deny every other change with AccessControlException."});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "hdfs_describe_directory", "handler": {"type": "static", "actions": [
                {"type": DIRECTORY, "entries": [{"name": "data", "kind": "dir", "entries": [{"name": "sales.csv", "kind": "file", "text": "region,total\nnorth,10\n"}]}]}]}},
            {"event_pattern": "hdfs_connect", "handler": {"type": "static", "actions": [{"type": ALLOW}]}},
            {"event_pattern": "*", "handler": {"type": "static", "actions": [{"type": DENY, "exception": "AccessControlException", "message": "read-only"}]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin)\nt=i['event_type_id']; e=i['event']\nif t=='hdfs_describe_directory':\n  a={'type':'hdfs_directory','entries':[{'name':'user','kind':'dir','entries':[{'name':'alice','kind':'dir','owner':'alice'}]}] if e['path']=='/' else []}\nelif t=='hdfs_connect':\n  a={'type':'hdfs_allow'} if e['user'] in ('alice','hdfs') else {'type':'hdfs_deny','message':'unknown user'}\nelif e['path'].startswith('/user/alice/'):\n  a={'type':'hdfs_allow'}\nelse:\n  a={'type':'hdfs_deny','exception':'AccessControlException','message':'Permission denied'}\nprint(json.dumps({'actions':[a]}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Server for HdfsProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        check(&v)?;
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}

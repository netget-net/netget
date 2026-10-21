//! What the model does as an HDFS client: list a directory, stat a path, read a byte range,
//! make directories, write a file, delete, rename and change permissions. Each result comes
//! back as an event; an exception the NameNode or DataNode raised comes back as `hdfs_error`
//! with its Java class.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::{log_template::LogTemplate, ConnectContext, EventType};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const LIST: &str = "hdfs_list";
pub const STAT: &str = "hdfs_stat";
pub const READ: &str = "hdfs_read";
pub const MKDIR: &str = "hdfs_mkdir";
pub const WRITE: &str = "hdfs_write";
pub const DELETE: &str = "hdfs_delete";
pub const RENAME: &str = "hdfs_rename";
pub const SET_PERMISSION: &str = "hdfs_set_permission";

/// Bytes one read returns, so a result fits in an event.
pub const MAX_READ: u64 = 64 * 1024;
pub const DEFAULT_READ: u64 = 4096;
/// Bytes one write sends.
pub const MAX_WRITE: usize = 1 << 20;
/// Entries of a listing page shown in one event.
pub const MAX_LISTED: usize = 200;

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
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(format!("-> {name} {{path}}"))),
    }
}

fn path_param() -> Parameter {
    p(
        "path",
        "string",
        "An absolute HDFS path, e.g. /user/alice/a.txt",
        true,
    )
}

pub fn client_actions() -> Vec<ActionDefinition> {
    vec![
        action(
            LIST,
            "List a directory (getListing): up to 200 entries per result, in name order; pass \
             the last name shown as start_after for the next page. Arrives as hdfs_listing.",
            vec![
                path_param(),
                p(
                    "start_after",
                    "string",
                    "List only names after this one (paging)",
                    false,
                ),
            ],
            json!({"type": LIST, "path": "/user"}),
        ),
        action(
            STAT,
            "Stat a path (getFileInfo): kind, length, mode, owner, group, times, replication and \
             block size, or that it does not exist. Arrives as hdfs_file_status.",
            vec![path_param()],
            json!({"type": STAT, "path": "/user/alice/a.txt"}),
        ),
        action(
            READ,
            "Read bytes of a file: the NameNode's block locations, then each block's bytes from \
             a DataNode with every chunk's checksum verified (at most 65536 bytes). The data \
             comes back as text when it is text and as hex otherwise; ask for hex to always get \
             hex. Arrives as hdfs_read_result.",
            vec![
                path_param(),
                p("offset", "number", "The first byte (default 0)", false),
                p(
                    "length",
                    "number",
                    "How many bytes (default 4096, at most 65536)",
                    false,
                ),
                p(
                    "encoding",
                    "string",
                    "utf8 (default: text when it is text) or hex",
                    false,
                ),
            ],
            json!({"type": READ, "path": "/user/alice/a.txt", "offset": 0, "length": 4096}),
        ),
        action(
            MKDIR,
            "Make a directory and, by default, its missing parents (mkdirs). Arrives as \
             hdfs_mutation_result.",
            vec![
                path_param(),
                p(
                    "mode",
                    "number",
                    "Permission bits, decimal (default 493, which is 0755)",
                    false,
                ),
                p(
                    "create_parent",
                    "boolean",
                    "Make missing parents too (default true)",
                    false,
                ),
            ],
            json!({"type": MKDIR, "path": "/user/alice/reports"}),
        ),
        action(
            WRITE,
            "Write a whole file (create, addBlock, the DataNode pipeline with CRC32C chunk \
             checksums and packet acks, complete), at most 1 MiB. Arrives as \
             hdfs_write_result.",
            vec![
                path_param(),
                p(
                    "data",
                    "string",
                    "The file's content: the text itself for utf8, pairs of hex digits for hex",
                    true,
                ),
                p(
                    "encoding",
                    "string",
                    "How data is written: utf8 (the text's bytes; default) or hex (pairs of hex \
                     digits, for binary)",
                    false,
                ),
                p(
                    "overwrite",
                    "boolean",
                    "Replace an existing file (default false)",
                    false,
                ),
                p(
                    "mode",
                    "number",
                    "Permission bits, decimal (default 420, which is 0644)",
                    false,
                ),
                p("replication", "number", "Replication (default 1)", false),
                p(
                    "block_size",
                    "number",
                    "Block size in bytes, a multiple of 512 (default 134217728)",
                    false,
                ),
            ],
            json!({"type": WRITE, "path": "/user/alice/hello.txt", "data": "hello from netget\n", "encoding": "utf8"}),
        ),
        action(
            DELETE,
            "Delete a file or directory (delete). Arrives as hdfs_mutation_result (result false \
             when nothing was there).",
            vec![
                path_param(),
                p(
                    "recursive",
                    "boolean",
                    "Delete a non-empty directory with everything in it (default false)",
                    false,
                ),
            ],
            json!({"type": DELETE, "path": "/user/alice/old.txt"}),
        ),
        action(
            RENAME,
            "Move or rename a path (rename2). Arrives as hdfs_mutation_result.",
            vec![
                path_param(),
                p("destination", "string", "The new absolute path", true),
                p(
                    "overwrite",
                    "boolean",
                    "Replace what is at destination (default false)",
                    false,
                ),
            ],
            json!({"type": RENAME, "path": "/user/alice/a.txt", "destination": "/user/alice/b.txt"}),
        ),
        action(
            SET_PERMISSION,
            "Change a path's permission bits (setPermission). Arrives as hdfs_mutation_result.",
            vec![
                path_param(),
                p(
                    "mode",
                    "number",
                    "Permission bits, decimal (416 is 0640)",
                    true,
                ),
            ],
            json!({"type": SET_PERMISSION, "path": "/user/alice/a.txt", "mode": 416}),
        ),
        action(
            "disconnect",
            "Close the NameNode connection and stop this client.",
            vec![],
            json!({"type": "disconnect"}),
        ),
    ]
}

fn status_params() -> &'static str {
    "{name, kind (file|dir|symlink), length, mode (decimal), owner, group, modification_time and \
     access_time (Unix milliseconds), replication, block_size, symlink_target}"
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hdfs_connected",
        "The HDFS client reached the NameNode (getServerDefaults answered). List, stat, read, \
         write or change paths.",
        json!({"type": LIST, "path": "/"}),
    )
    .with_parameters(vec![
        p("remote_addr", "string", "The NameNode's address", true),
        p("user", "string", "The user this client connects as", true),
        p(
            "server_defaults",
            "object",
            "block_size, bytes_per_checksum, replication, checksum_type, write_packet_size",
            true,
        ),
    ])
    .with_actions(client_actions())
});

pub static LISTING_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hdfs_listing",
        "A directory listing page.",
        json!({"type": STAT, "path": "/user"}),
    )
    .with_parameters(vec![
        p("path", "string", "The directory listed", true),
        p(
            "entries",
            "array",
            &format!("The entries: {}", status_params()),
            true,
        ),
        p(
            "remaining",
            "number",
            "Entries after this page; list again with start_after the last name",
            true,
        ),
    ])
    .with_actions(client_actions())
});

pub static STATUS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hdfs_file_status",
        "A path's status, or that it does not exist.",
        json!({"type": READ, "path": "/user/alice/a.txt"}),
    )
    .with_parameters(vec![
        p("path", "string", "The absolute HDFS path it is about", true),
        p("exists", "boolean", "Whether it exists", true),
        p("status", "object", status_params(), false),
    ])
    .with_actions(client_actions())
});

pub static READ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hdfs_read_result",
        "Bytes read from a file, every chunk's checksum verified.",
        json!({"type": READ, "path": "/user/alice/a.txt", "offset": 4096}),
    )
    .with_parameters(vec![
        p("path", "string", "The absolute HDFS path of the file", true),
        p("offset", "number", "The first byte read", true),
        p("bytes", "number", "How many bytes data holds", true),
        p(
            "data",
            "string",
            "The bytes, in the encoding named beside it",
            true,
        ),
        p(
            "encoding",
            "string",
            "utf8 (data is the text) or hex (data is hex digits)",
            true,
        ),
        p("file_length", "number", "The file's length", true),
        p(
            "eof",
            "boolean",
            "Whether the read reached the end of the file",
            true,
        ),
        p(
            "datanodes",
            "array",
            "The DataNodes the blocks were read from (address:port)",
            true,
        ),
    ])
    .with_actions(client_actions())
});

pub static WRITE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hdfs_write_result",
        "A file was written: created, its blocks streamed through the DataNode pipeline and \
         acknowledged, and completed.",
        json!({"type": READ, "path": "/user/alice/hello.txt"}),
    )
    .with_parameters(vec![
        p("path", "string", "The absolute HDFS path of the file", true),
        p("bytes", "number", "How many bytes were written", true),
        p("blocks", "number", "How many blocks were written", true),
        p(
            "datanodes",
            "array",
            "The DataNodes each block went to (address:port)",
            true,
        ),
    ])
    .with_actions(client_actions())
});

pub static MUTATION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hdfs_mutation_result",
        "A change the NameNode answered: mkdir, delete, rename or set_permission.",
        json!({"type": STAT, "path": "/user/alice/reports"}),
    )
    .with_parameters(vec![
        p(
            "operation",
            "string",
            "mkdir, delete, rename or set_permission",
            true,
        ),
        p("path", "string", "The absolute HDFS path it is about", true),
        p("destination", "string", "rename: the new path", false),
        p(
            "result",
            "boolean",
            "What the NameNode answered (delete: false when nothing was there)",
            true,
        ),
    ])
    .with_actions(client_actions())
});

pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "hdfs_error",
        "An operation failed: the NameNode or a DataNode raised an exception (exception_class \
         and message are Hadoop's own), or the connection failed.",
        json!({"type": STAT, "path": "/user/alice"}),
    )
    .with_parameters(vec![
        p("operation", "string", "The action that failed", true),
        p("path", "string", "The path it was for", true),
        p(
            "exception_class",
            "string",
            "The Java exception class, e.g. java.io.FileNotFoundException or \
             org.apache.hadoop.security.AccessControlException (empty for a transport failure)",
            true,
        ),
        p(
            "message",
            "string",
            "The exception's message, or what failed",
            true,
        ),
    ])
    .with_actions(client_actions())
});

/// The bytes of a write action's data.
pub fn write_data(v: &Value) -> Result<Vec<u8>> {
    let data = v["data"].as_str().context("data is text")?;
    let bytes = match v["encoding"].as_str().unwrap_or("utf8") {
        "utf8" => data.as_bytes().to_vec(),
        "hex" => hex::decode(data.trim()).context("data is not hex")?,
        other => bail!("encoding is utf8 or hex, not {other:?}"),
    };
    ensure!(
        bytes.len() <= MAX_WRITE,
        "data is at most {MAX_WRITE} bytes"
    );
    Ok(bytes)
}

fn check_path(v: &Value, key: &str) -> Result<()> {
    let p = v[key]
        .as_str()
        .with_context(|| format!("{key} is a path"))?;
    crate::server::hdfs::namespace::components(p).map_err(|t| anyhow::anyhow!("{}", t.message))?;
    Ok(())
}

fn check_mode(v: &Value, required: bool) -> Result<()> {
    match &v["mode"] {
        Value::Null if !required => Ok(()),
        m => {
            let m = m.as_u64().context("mode is a decimal number")?;
            ensure!(m <= 0o7777, "mode is at most 4095 (07777)");
            Ok(())
        }
    }
}

fn check_bool(v: &Value, key: &str) -> Result<()> {
    ensure!(
        v[key].is_null() || v[key].is_boolean(),
        "{key} is true or false"
    );
    Ok(())
}

/// Check an action's fields.
pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        LIST => {
            check_path(v, "path")?;
            ensure!(
                v["start_after"].is_null() || v["start_after"].is_string(),
                "start_after is a name"
            );
        }
        STAT => check_path(v, "path")?,
        READ => {
            check_path(v, "path")?;
            ensure!(
                v["offset"].is_null() || v["offset"].as_u64().is_some(),
                "offset is a number"
            );
            match &v["length"] {
                Value::Null => {}
                l => ensure!(
                    l.as_u64().is_some_and(|l| (1..=MAX_READ).contains(&l)),
                    "length is 1 to {MAX_READ}"
                ),
            }
            ensure!(
                matches!(v["encoding"].as_str(), None | Some("utf8" | "hex")),
                "encoding is utf8 or hex"
            );
        }
        MKDIR => {
            check_path(v, "path")?;
            check_mode(v, false)?;
            check_bool(v, "create_parent")?;
        }
        WRITE => {
            check_path(v, "path")?;
            write_data(v)?;
            check_mode(v, false)?;
            check_bool(v, "overwrite")?;
            if !v["replication"].is_null() {
                crate::server::hdfs::namespace::check_replication(
                    v["replication"]
                        .as_u64()
                        .context("replication is a number")?,
                )?;
            }
            if !v["block_size"].is_null() {
                let b = v["block_size"].as_u64().context("block_size is a number")?;
                ensure!(
                    b >= 512 && b.is_multiple_of(512) && b <= 1 << 30,
                    "block_size is a multiple of 512 up to 1 GiB"
                );
            }
        }
        DELETE => {
            check_path(v, "path")?;
            check_bool(v, "recursive")?;
        }
        RENAME => {
            check_path(v, "path")?;
            check_path(v, "destination")?;
            check_bool(v, "overwrite")?;
        }
        SET_PERMISSION => {
            check_path(v, "path")?;
            check_mode(v, true)?;
        }
        other => bail!("Unknown HDFS client action {other:?}"),
    }
    Ok(())
}

#[derive(Default, Clone)]
pub struct HdfsClientProtocol;
impl HdfsClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for HdfsClientProtocol {
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
        "HDFS client: list, stat, read, write, mkdir, delete, rename and chmod against a \
         NameNode, reading and writing blocks through its DataNodes"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        client_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            LISTING_EVENT.clone(),
            STATUS_EVENT.clone(),
            READ_EVENT.clone(),
            WRITE_EVENT.clone(),
            MUTATION_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "user".into(),
            type_hint: "string".into(),
            description: "The user this client asserts (SIMPLE authentication: the NameNode \
                          takes the name on trust)"
                .into(),
            required: false,
            example: json!("alice"),
            default: Some(json!(super::DEFAULT_USER)),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Hand-written HDFS client over the server's Hadoop IPC and DataTransferProtocol modules (src/server/hdfs/rpc.rs, transfer.rs, Hadoop 3.5.0's .proto files): the hrpc header with SIMPLE authentication and a connection context, ClientNamenodeProtocol calls correlated by call id (getServerDefaults, getListing, getFileInfo, getBlockLocations, mkdirs, create, addBlock, complete, delete, rename2, setPermission), READ_BLOCK with checksum verification and WRITE_BLOCK through the NameNode's pipeline with packet acks")
            .llm_control("Which paths to list, stat and read (offset, length, encoding), which directories to make, what to write where, and what to delete, rename or chmod")
            .e2e_testing("tests/client/hdfs: a real single-node HDFS from Apache Hadoop 3.5.0 (hdfs namenode -format, a NameNode and a DataNode on loopback ports), the files the client writes read back with hdfs dfs -cat, what it reads seeded with hdfs dfs -put, and the model's actions asserted on the NameNode's own audit log; in the hdfs pair job")
            .notes("Experimental: one independent peer (Apache Hadoop 3.5.0's NameNode and DataNode) passes on macOS; in CI it runs only in the hdfs pair job, which had not run when this landed. SIMPLE authentication only (no Kerberos, no SASL, no data transfer encryption or block tokens). Reads move at most 64 KiB and writes at most 1 MiB per action; read data is text only when it is text, hex otherwise; a listing event shows at most 200 entries. No append, no hflush, no pipeline recovery: a DataNode failing mid-write fails the write. A handler chain stops after 16 follow-ups (a whole list, stat, read, write, rename, chmod and delete session is twelve). Response frames are bounded at 16 MiB.")
            .history(HistoryMode::Last(SESSION_HISTORY_ENTRIES))
            .batching(BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the HDFS NameNode at 10.0.0.5:8020 as alice, list /user/alice and read the first file"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_client", "protocol": "hdfs", "remote_addr": "127.0.0.1:8020",
            "startup_params": {"user": "alice"},
            "instruction": "List /user/alice, then read the first file in it"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "hdfs_connected", "handler": {"type": "static", "actions": [{"type": LIST, "path": "/user/alice"}]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin)\nt=i['event_type_id']; e=i['event']\nif t=='hdfs_connected':\n  a=[{'type':'hdfs_list','path':'/user/alice'}]\nelif t=='hdfs_listing':\n  f=[x for x in e['entries'] if x['kind']=='file']\n  a=[{'type':'hdfs_read','path':e['path'].rstrip('/')+'/'+f[0]['name']}] if f else []\nelse:\n  a=[]\nprint(json.dumps({'actions':a}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Client for HdfsClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        if name == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v)?;
        Ok(ClientActionResult::Custom { name, data: v })
    }
}

//! What the model decides for a FUSE mount: what each directory contains (asked once, the first
//! time something looks inside it) and whether each change a local process asks for may happen.
//! Reads, lookups, listings, getattr and readlink are answered from the description at no model
//! cost; every create, write, truncate, attribute change, mkdir, unlink, rmdir, rename and
//! symlink is one decision, accepted into the mount's in-memory overlay or refused with the
//! errno the model names.
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::dependencies::ProtocolDependency;
use crate::protocol::{log_template::LogTemplate, EventType, SpawnContext};
use crate::server::described_tree::{self, errno_named, ERRNO_NAMES};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

pub const DIRECTORY: &str = "fuse_directory";
pub const ALLOW: &str = "fuse_allow";
pub const DENY: &str = "fuse_deny";

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
        DIRECTORY => LogTemplate::new().with_info("-> FUSE directory {preview(entries,120)}"),
        DENY => LogTemplate::new().with_info("-> FUSE deny {error}"),
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
        "Describe the directory's entries. NetGet serves every lookup, listing, stat, read and \
         readlink from this description without asking again. A file's content is text \
         (UTF-8), hex, or extents over its size like a described disk ({offset, text} | \
         {offset, hex} | {offset, length, fill: 0-255}; bytes no extent covers read as \
         zeroes); errors are byte ranges whose reads fail with an errno. A subdirectory may \
         carry its own entries (described now) or none (asked about when first opened).",
        vec![p(
            "entries",
            "array",
            "[{name, kind: file|dir|symlink, mode (decimal permission bits: 420 is 0644, 493 \
             is 0755), uid, gid, mtime/atime/ctime (Unix seconds); file: text | hex | \
             extents with size, size (default: the text's length), errors ([{offset, length, \
             error: EIO|EACCES|...}]); dir: entries (optional, nested the same way); symlink: \
             target}], at most 4096 per directory and 16384 per answer, names 1-255 bytes \
             without '/', 64 directories deep, 16 MiB of text and hex over the whole mount, \
             files up to 1 GiB",
            true,
        )],
        json!({"type": DIRECTORY, "entries": [
            {"name": "README.txt", "kind": "file", "text": "hello from netget\n", "mode": 420},
            {"name": "disk.img", "kind": "file", "size": 8192,
             "extents": [{"offset": 0, "hex": "deadbeef"}, {"offset": 4096, "length": 4096, "fill": 255}]},
            {"name": "docs", "kind": "dir", "entries": [{"name": "a.md", "kind": "file", "text": "# A\n"}]},
            {"name": "src", "kind": "dir"},
            {"name": "latest", "kind": "symlink", "target": "README.txt"}
        ]}),
    )
}

pub fn allow_action() -> ActionDefinition {
    action(
        ALLOW,
        "Let the change happen. NetGet applies it to the mount's in-memory overlay, which lasts \
         until the mount is stopped, and the process gets success.",
        vec![],
        json!({"type": ALLOW}),
    )
}

pub fn deny_action() -> ActionDefinition {
    action(
        DENY,
        "Refuse: the process's system call fails with this errno and nothing changes. For a \
         directory description, every lookup and listing in it fails the same way.",
        vec![p(
            "error",
            "string",
            &format!("The errno: {ERRNO_NAMES}"),
            true,
        )],
        json!({"type": DENY, "error": "EACCES"}),
    )
}

fn who() -> Vec<Parameter> {
    vec![
        p(
            "pid",
            "number",
            "The process asking (0 when the kernel asks on its own)",
            true,
        ),
        p("uid", "number", "The process's user id", true),
        p("gid", "number", "The process's group id", true),
        p(
            "process",
            "string",
            "The process's command name, from /proc/<pid>/comm",
            false,
        ),
    ]
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

fn path() -> Parameter {
    p(
        "path",
        "string",
        "The path inside the mount, from its root",
        true,
    )
}

pub static DESCRIBE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    let mut parameters = vec![
        path(),
        p(
            "depth",
            "number",
            "Directories between it and the mount's root (the root is 0)",
            true,
        ),
        p(
            "operation",
            "string",
            "What looked inside: lookup (a name in it was opened or stat'ed) or readdir (it was \
             listed)",
            true,
        ),
        p("name", "string", "The name looked up, for a lookup", false),
    ];
    parameters.extend(who());
    EventType::new(
        "fuse_describe_directory",
        "A process looked inside a directory nobody has described yet. Answer fuse_directory \
         with its entries (asked once per directory for the life of the mount), or fuse_deny.",
        directory_action().example,
    )
    .with_parameters(parameters)
    .with_actions(vec![directory_action(), deny_action()])
    .with_log_template(LogTemplate::new().with_info("FUSE describe {path} ({operation})"))
});

pub static CREATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "fuse_create",
        "A process creates a file: a regular file (open with O_CREAT), or a FIFO, socket or \
         device node (mkfifo, bind, mknod). Allow it (it appears, empty) or deny it.",
        vec![
            path(),
            p(
                "mode",
                "number",
                "The permission bits asked for (decimal)",
                true,
            ),
            p(
                "kind",
                "string",
                "file, fifo, socket, char or block (device nodes cannot be opened: the mount is \
                 nodev)",
                true,
            ),
            p(
                "flags",
                "number",
                "The open(2) flags, for a regular file",
                false,
            ),
            p(
                "rdev",
                "number",
                "The device number, for a device node",
                false,
            ),
        ],
        "FUSE create {path}",
    )
});

pub static WRITE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "fuse_write",
        "A process writes to a file. Allow it (the bytes land in the overlay and read back) or \
         deny it (nothing changes).",
        vec![
            path(),
            p("offset", "number", "Byte offset of the write", true),
            p("length", "number", "Bytes the process wrote", true),
            p(
                "size_before",
                "number",
                "The file's size before the write",
                true,
            ),
            p(
                "data",
                "string",
                "The first bytes written, in the encoding named beside it",
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
            p("flags", "number", "The file's open(2) flags", false),
        ],
        "FUSE write {path} offset={offset} length={length}",
    )
});

pub static TRUNCATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "fuse_truncate",
        "A process changes a file's size (truncate, ftruncate, open with O_TRUNC). Allow or \
         deny.",
        vec![
            path(),
            p("size", "number", "The new size in bytes", true),
            p("size_before", "number", "The size before", true),
        ],
        "FUSE truncate {path} to {size}",
    )
});

pub static SETATTR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "fuse_setattr",
        "A process changes a file's attributes (chmod, chown, utimes/touch). Only the fields \
         present change. Allow or deny.",
        vec![
            path(),
            p("mode", "number", "New permission bits (decimal)", false),
            p("owner_uid", "number", "The new owner's user id", false),
            p("owner_gid", "number", "The new group id", false),
            p("atime", "number", "New access time, Unix seconds", false),
            p(
                "mtime",
                "number",
                "New modification time, Unix seconds",
                false,
            ),
        ],
        "FUSE setattr {path}",
    )
});

pub static MKDIR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "fuse_mkdir",
        "A process makes a directory. Allow it (an empty directory appears) or deny it.",
        vec![
            path(),
            p(
                "mode",
                "number",
                "The permission bits asked for (decimal)",
                true,
            ),
        ],
        "FUSE mkdir {path}",
    )
});

pub static UNLINK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "fuse_unlink",
        "A process removes a file or symlink. Allow or deny.",
        vec![path(), p("kind", "string", "file or symlink", true)],
        "FUSE unlink {path}",
    )
});

pub static RMDIR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "fuse_rmdir",
        "A process removes an empty directory. Allow or deny.",
        vec![path()],
        "FUSE rmdir {path}",
    )
});

pub static RENAME_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "fuse_rename",
        "A process moves or renames an entry; if new_path exists it is replaced. Allow or deny.",
        vec![
            path(),
            p("new_path", "string", "The path it moves to", true),
            p("kind", "string", "file, dir or symlink", true),
            p(
                "replaces",
                "boolean",
                "Whether something at new_path is replaced",
                true,
            ),
        ],
        "FUSE rename {path} -> {new_path}",
    )
});

pub static SYMLINK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    change_event(
        "fuse_symlink",
        "A process makes a symbolic link. Allow or deny.",
        vec![
            path(),
            p("target", "string", "What the link points to", true),
        ],
        "FUSE symlink {path} -> {target}",
    )
});

/// Check an answer's shape: what the executor accepts before the mount looks at it in place.
pub fn check(v: &Value) -> Result<()> {
    match v["type"].as_str().unwrap_or_default() {
        DIRECTORY => {
            described_tree::check_description(v)?;
        }
        ALLOW => {}
        DENY => {
            let name = v["error"].as_str().unwrap_or_default();
            ensure!(errno_named(name).is_some(), "error is one of {ERRNO_NAMES}");
        }
        other => bail!("Unknown FUSE action {other:?}"),
    }
    Ok(())
}

#[derive(Default, Clone)]
pub struct FuseProtocol;
impl FuseProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Protocol for FuseProtocol {
    /// A mount has no host and no port: `mount_point` names where it appears.
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        Some(crate::protocol::BindingDefaults {
            mac_address: None,
            interface: None,
            host: None,
            port: None,
        })
    }
    fn protocol_name(&self) -> &'static str {
        "FUSE"
    }
    fn stack_name(&self) -> &'static str {
        "VFS>FUSE"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "fuse",
            "fuse filesystem",
            "fuse mount",
            "filesystem in userspace",
            "fusermount",
        ]
    }
    fn description(&self) -> &'static str {
        "FUSE local filesystem (Linux): a directory on this machine whose contents the model \
         describes and whose every change it decides; the kernel is the client, NetGet serves \
         reads from the description and keeps accepted changes in memory"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![directory_action(), allow_action(), deny_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            DESCRIBE_EVENT.clone(),
            CREATE_EVENT.clone(),
            WRITE_EVENT.clone(),
            TRUNCATE_EVENT.clone(),
            SETATTR_EVENT.clone(),
            MKDIR_EVENT.clone(),
            UNLINK_EVENT.clone(),
            RMDIR_EVENT.clone(),
            RENAME_EVENT.clone(),
            SYMLINK_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "mount_point".into(),
                type_hint: "string".into(),
                description: "The directory the filesystem appears at: an existing empty \
                              directory, or a new one in an existing directory (created, and \
                              removed again when the mount stops)"
                    .into(),
                required: true,
                example: json!("/tmp/netget-fuse"),
                default: None,
            },
            ParameterDefinition {
                name: "read_only".into(),
                type_hint: "boolean".into(),
                description: "Mount read-only: every change fails with EROFS and the model is \
                              never asked about one"
                    .into(),
                required: false,
                example: json!(false),
                default: None,
            },
            ParameterDefinition {
                name: "allow_other".into(),
                type_hint: "boolean".into(),
                description: "Let other users (root included) use the mount; the kernel still \
                              checks each file's mode. Needs root, or user_allow_other in \
                              /etc/fuse.conf"
                    .into(),
                required: false,
                example: json!(false),
                default: None,
            },
            ParameterDefinition {
                name: "decision_timeout_secs".into(),
                type_hint: "number".into(),
                description: "How long a process waits for a description or a decision before \
                              its system call fails with EIO (1-600)"
                    .into(),
                required: false,
                example: json!(30),
                default: Some(json!(super::DEFAULT_DECISION_TIMEOUT.as_secs())),
            },
            ParameterDefinition {
                name: "max_overlay_bytes".into(),
                type_hint: "number".into(),
                description: "Bytes of accepted writes (whole 4 KiB pages) and symlink targets \
                              the mount holds in memory; past it a write fails with ENOSPC \
                              (up to 1 GiB)"
                    .into(),
                required: false,
                example: json!(16777216),
                default: Some(json!(described_tree::DEFAULT_MAX_OVERLAY_BYTES)),
            },
        ]
    }
    fn get_dependencies(&self) -> Vec<ProtocolDependency> {
        let mut deps =
            crate::llm::actions::protocol_trait::default_dependencies_from_privilege(self);
        deps.push(ProtocolDependency::ToolInPath("fusermount3"));
        deps
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Linux FUSE through the fuser crate (0.18, MIT, no libfuse: /dev/fuse is mounted by the setuid fusermount3 helper with auto_unmount, and fuser speaks the kernel protocol); a lazily described file tree with an in-memory overlay (src/server/described_tree.rs, content through src/server/described_disk.rs); one worker per mount asks the model one decision at a time under a deadline")
            .llm_control("What each directory contains (names, kinds, modes, owners, times, file content as text/hex/extents with failing regions, symlink targets), asked once per directory when something first looks inside it; and every change a process asks for - create, write, truncate, chmod/chown/utimes, mkdir, unlink, rmdir, rename, symlink - allowed into the overlay or refused with an errno")
            .e2e_testing("tests/server/fuse: ordinary tools on the mount (ls, stat, cat, dd at offsets, find, sha256sum against the described bytes, cp in and out, mv, rm, mkdir/rmdir, ln -s/readlink, chmod, truncate) and Python's os.walk/os.stat/open as separate processes, with the model calls each operation caused; deadline, model failure, depth, overlay and refused-write bounds; stop and a killed daemon unmount; pjdfstest (the C suite) on the mount, 198 of 238 files passing in full, the rest on hard links, device nodes in a user namespace and the 1 GiB file bound; Linux only, in the fuse pair job. There is no wire: the kernel's FUSE driver is the peer, so no pcap oracle applies")
            .notes("Experimental: the peer is the Linux kernel's FUSE driver driven by coreutils, findutils, Python and pjdfstest, measured on a Linux 7.2 aarch64 kernel; in CI only the fuse pair job runs it, which had not run when this landed. Linux only (no macFUSE or FUSE-T: NetGet links neither). FIFOs, sockets and device nodes are names only (the kernel serves their I/O; the mount is nodev). Not implemented: hard links (EPERM), extended attributes (none listed; setting one is ENOTSUP), file locks beyond the kernel's own, fallocate. A description, decision or model failure past decision_timeout_secs is EIO; a model refusal is its errno. Bounds: 65536 entries, 4096 per directory, names of 255 bytes, 64 directories deep, files up to 1 GiB, 16 MiB of described text and hex, the overlay (default 64 MiB), 128 KiB per write request, 64 requests waiting for the model, three description attempts per directory.")
            .answers_on_failure()
            .request_only("The kernel asks and the daemon answers: a FUSE daemon sends nothing that is not the reply to a kernel request, and this one sends no notifications")
            .max_inbound_bytes(super::MAX_WRITE_BYTES as usize)
            .history(HistoryMode::Last(SESSION_HISTORY_ENTRIES))
            .batching(BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Mount a FUSE filesystem at /tmp/netget-fuse with a README and a notes directory; allow writes under notes only"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({"type": "open_server", "base_stack": "fuse",
            "startup_params": {"mount_point": "/tmp/netget-fuse"},
            "instruction": "The root holds README.txt (text: 'hello from netget') and an empty notes directory. Allow creates and writes inside /notes; deny every other change with EACCES."});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "fuse_describe_directory", "handler": {"type": "static", "actions": [
                {"type": DIRECTORY, "entries": [{"name": "README.txt", "kind": "file", "text": "hello from netget\n"}]}]}},
            {"event_pattern": "*", "handler": {"type": "static", "actions": [{"type": DENY, "error": "EROFS"}]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern": "*", "handler": {"type": "script", "language": "python",
            "code": "import json,sys\ni=json.load(sys.stdin)\nt=i['event_type_id']; e=i['event']\nif t=='fuse_describe_directory':\n  a={'type':'fuse_directory','entries':[{'name':'README.txt','kind':'file','text':'hello\\n'},{'name':'notes','kind':'dir','entries':[]}] if e['path']=='/' else []}\nelif e['path'].startswith('/notes/'):\n  a={'type':'fuse_allow'}\nelse:\n  a={'type':'fuse_deny','error':'EACCES'}\nprint(json.dumps({'actions':[a]}))"}}]);
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Server for FuseProtocol {
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

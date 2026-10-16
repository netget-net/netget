//! AFP server actions and events: what the model decides about the files behind the server.
//!
//! Rust owns the session — DSI framing, request IDs, the login and its password check, volume
//! and fork reference numbers, CNIDs, bitmaps, names, dates and every bound. The model owns the
//! content: which volumes exist, what each directory holds, what each file says, and whether a
//! create, a write or a delete is accepted. Six events, all raised in `src/server/afp/mod.rs`:
//!
//! - `afp_list_volumes` — a client asked which volumes exist (unless `volumes` is configured)
//! - `afp_list_directory` — a client looked inside a directory NetGet has not listed yet
//! - `afp_read_file` — a client opened a file to read it
//! - `afp_write_file` — a client wrote to a file or set its length
//! - `afp_create` — a client created a file or a directory
//! - `afp_delete` — a client deleted a file or a directory
use super::wire;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// How long a client may stay silent (no request, no tickle) before its session is closed.
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;
pub const MAX_IDLE_TIMEOUT_SECS: u64 = 86_400;
/// The most entries one directory listing from the model may hold.
pub const MAX_DIR_ENTRIES: usize = 4096;
/// The most bytes one file's content from the model may hold.
pub const MAX_FILE_BYTES: usize = 16 * 1024 * 1024;
/// The server name used when none is configured.
pub const DEFAULT_SERVER_NAME: &str = "NetGet";

/// `Custom` result names shared with `mod.rs`.
pub const RESULT_VOLUMES: &str = "afp_volumes";
pub const RESULT_LISTING: &str = "afp_directory_listing";
pub const RESULT_CONTENT: &str = "afp_file_content";
pub const RESULT_ALLOW: &str = "afp_allow";
pub const RESULT_DENY: &str = "afp_deny";

#[derive(Clone, Default)]
pub struct AfpProtocol;

impl AfpProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required,
    }
}

fn volumes_action() -> ActionDefinition {
    ActionDefinition {
        name: "afp_volumes".into(),
        description: format!(
            "Answer afp_list_volumes: the volumes (shares) this server offers, at most {}. \
             Each is {{\"name\"}} (at most 27 characters as Macs show it) with optional \
             read_only (true refuses every create, write and delete on it without asking you) \
             and created (RFC 3339)",
            wire::MAX_VOLUMES
        ),
        parameters: vec![p(
            "volumes",
            "array",
            "The volumes, e.g. [{\"name\": \"Projects\"}, {\"name\": \"Archive\", \
             \"read_only\": true}]",
            true,
        )],
        example: json!({
            "type": "afp_volumes",
            "volumes": [{"name": "Projects"}, {"name": "Archive", "read_only": true}]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("AFP volumes listed")
                .with_debug("AFP volumes: {json(.)}"),
        ),
    }
}

fn listing_action() -> ActionDefinition {
    ActionDefinition {
        name: "afp_directory_listing".into(),
        description: format!(
            "Answer afp_list_directory with what the directory holds (at most \
             {MAX_DIR_ENTRIES} entries). Each entry is {{\"name\", \"type\": \"file\" or \
             \"directory\"}} with optional size (bytes, files), created and modified (RFC \
             3339), permissions (octal Unix mode, e.g. \"644\") and read_only. NetGet assigns \
             the IDs and remembers the listing for the rest of the session; a client reading \
             a file asks you for its content separately"
        ),
        parameters: vec![p(
            "entries",
            "array",
            "The entries, e.g. [{\"name\": \"notes.txt\", \"type\": \"file\", \"size\": 12}, \
             {\"name\": \"photos\", \"type\": \"directory\"}]; [] for an empty directory",
            true,
        )],
        example: json!({
            "type": "afp_directory_listing",
            "entries": [
                {"name": "notes.txt", "type": "file", "size": 12, "modified": "2026-10-01T09:30:00Z"},
                {"name": "photos", "type": "directory"}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("AFP directory listed")
                .with_debug("AFP listing: {json(.)}"),
        ),
    }
}

fn content_action() -> ActionDefinition {
    ActionDefinition {
        name: "afp_file_content".into(),
        description: format!(
            "Answer afp_read_file with the file's content (at most {} MiB): text, or with \
             encoding \"hex\" bytes written as hex digits. The client sees exactly these \
             bytes, and their length becomes the file's size",
            MAX_FILE_BYTES / (1024 * 1024)
        ),
        parameters: vec![
            p("content", "string", "The file's content", true),
            p(
                "encoding",
                "string",
                "utf8 (the default: content is the text itself) or hex",
                false,
            ),
        ],
        example: json!({"type": "afp_file_content", "content": "Hello from NetGet\n"}),
        log_template: Some(LogTemplate::new().with_info("AFP file content supplied")),
    }
}

fn allow_action() -> ActionDefinition {
    ActionDefinition {
        name: "afp_allow".into(),
        description: "Accept the create, write or delete: the client is told it succeeded, and \
                      NetGet updates the listing it remembers for this session (a created \
                      file appears, empty; a deleted one disappears; a write changes the size)"
            .into(),
        parameters: vec![p("reason", "string", "Why, for the log", false)],
        example: json!({"type": "afp_allow"}),
        log_template: Some(LogTemplate::new().with_info("AFP operation allowed")),
    }
}

fn deny_action() -> ActionDefinition {
    ActionDefinition {
        name: "afp_deny".into(),
        description: "Refuse: answer with an AFP error. error is access_denied (the default), \
                      not_found, exists, disk_full, locked, busy or misc"
            .into(),
        parameters: vec![
            p(
                "error",
                "string",
                "access_denied, not_found, exists, disk_full, locked, busy or misc",
                false,
            ),
            p("reason", "string", "Why, for the log", false),
        ],
        example: json!({"type": "afp_deny", "error": "access_denied", "reason": "read-only share"}),
        log_template: Some(LogTemplate::new().with_info("AFP operation denied")),
    }
}

pub static VOLUMES_ACTION: LazyLock<ActionDefinition> = LazyLock::new(volumes_action);
pub static LISTING_ACTION: LazyLock<ActionDefinition> = LazyLock::new(listing_action);
pub static CONTENT_ACTION: LazyLock<ActionDefinition> = LazyLock::new(content_action);
pub static ALLOW_ACTION: LazyLock<ActionDefinition> = LazyLock::new(allow_action);
pub static DENY_ACTION: LazyLock<ActionDefinition> = LazyLock::new(deny_action);

fn user_param() -> Parameter {
    p(
        "user",
        "string",
        "Who is logged in: the configured user name, or \"guest\"",
        true,
    )
}

fn volume_param() -> Parameter {
    p("volume", "string", "The volume's name", true)
}

fn path_param(what: &str) -> Parameter {
    p(
        "path",
        "string",
        &format!("{what}, relative to the volume's root, '/'-separated (\"\" is the root)"),
        true,
    )
}

pub static LIST_VOLUMES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "afp_list_volumes",
        "A client asked which volumes this server offers (FPGetSrvrParms, or FPOpenVol before \
         any listing). Answer with afp_volumes; NetGet remembers the answer for the session",
        volumes_action().example,
    )
    .with_parameters(vec![user_param()])
    .with_actions(vec![VOLUMES_ACTION.clone(), DENY_ACTION.clone()])
    .with_log_template(
        LogTemplate::new()
            .with_info("AFP volume list requested by {user}")
            .with_debug("AFP list volumes: {json(.)}"),
    )
});

pub static LIST_DIRECTORY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "afp_list_directory",
        "A client looked inside a directory (FPEnumerate, FPGetFileDirParms, or a path through \
         it). Answer with afp_directory_listing, or afp_deny (not_found, access_denied)",
        listing_action().example,
    )
    .with_parameters(vec![
        user_param(),
        volume_param(),
        path_param("The directory"),
    ])
    .with_actions(vec![LISTING_ACTION.clone(), DENY_ACTION.clone()])
    .with_alternative_example(json!({"type": "afp_deny", "error": "not_found"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("AFP list {volume}:/{path}")
            .with_debug("AFP list directory: {json(.)}"),
    )
});

pub static READ_FILE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "afp_read_file",
        "A client opened a file to read it (FPOpenFork). Answer with afp_file_content, or \
         afp_deny",
        content_action().example,
    )
    .with_parameters(vec![
        user_param(),
        volume_param(),
        path_param("The file"),
        p(
            "size",
            "number",
            "The size your listing gave the file, in bytes",
            false,
        ),
    ])
    .with_actions(vec![CONTENT_ACTION.clone(), DENY_ACTION.clone()])
    .with_alternative_example(json!({"type": "afp_deny", "error": "access_denied"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("AFP read {volume}:/{path}")
            .with_debug("AFP read file: {json(.)}"),
    )
});

pub static WRITE_FILE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "afp_write_file",
        "A client wrote to an open file (FPWrite, FPWriteExt) or set its length \
         (FPSetForkParms). Accept with afp_allow or refuse with afp_deny",
        json!({"type": "afp_allow"}),
    )
    .with_parameters(vec![
        user_param(),
        volume_param(),
        path_param("The file"),
        p(
            "operation",
            "string",
            "write (data at offset) or set_length (the file becomes length bytes long)",
            true,
        ),
        p("offset", "number", "Where the data goes, for write", false),
        p(
            "length",
            "number",
            "How many bytes are written, or the new length",
            true,
        ),
        p("data", "string", "The bytes written (text, or hex)", false),
        p(
            "encoding",
            "string",
            "utf8 when data is the text itself, hex when the bytes are not UTF-8",
            false,
        ),
    ])
    .with_actions(vec![ALLOW_ACTION.clone(), DENY_ACTION.clone()])
    .with_alternative_example(json!({"type": "afp_deny", "error": "disk_full"}))
    .with_log_template(
        LogTemplate::new()
            .with_info("AFP {operation} {volume}:/{path} ({length} bytes)")
            .with_debug("AFP write: {json(.)}"),
    )
});

pub static CREATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "afp_create",
        "A client created a file (FPCreateFile) or a directory (FPCreateDir). Accept with \
         afp_allow or refuse with afp_deny",
        json!({"type": "afp_allow"}),
    )
    .with_parameters(vec![
        user_param(),
        volume_param(),
        path_param("The new item"),
        p("kind", "string", "file or directory", true),
        p(
            "replace",
            "boolean",
            "A hard create: an existing file of that name is replaced by an empty one",
            false,
        ),
    ])
    .with_actions(vec![ALLOW_ACTION.clone(), DENY_ACTION.clone()])
    .with_log_template(
        LogTemplate::new()
            .with_info("AFP create {kind} {volume}:/{path}")
            .with_debug("AFP create: {json(.)}"),
    )
});

pub static DELETE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "afp_delete",
        "A client deleted a file or an empty directory (FPDelete). Accept with afp_allow or \
         refuse with afp_deny",
        json!({"type": "afp_allow"}),
    )
    .with_parameters(vec![
        user_param(),
        volume_param(),
        path_param("The item"),
        p("kind", "string", "file or directory", true),
    ])
    .with_actions(vec![ALLOW_ACTION.clone(), DENY_ACTION.clone()])
    .with_log_template(
        LogTemplate::new()
            .with_info("AFP delete {kind} {volume}:/{path}")
            .with_debug("AFP delete: {json(.)}"),
    )
});

pub fn event_types() -> Vec<EventType> {
    vec![
        LIST_VOLUMES_EVENT.clone(),
        LIST_DIRECTORY_EVENT.clone(),
        READ_FILE_EVENT.clone(),
        WRITE_FILE_EVENT.clone(),
        CREATE_EVENT.clone(),
        DELETE_EVENT.clone(),
    ]
}

/// A volume, as configured or as the model described it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeConfig {
    pub name: String,
    pub read_only: bool,
    pub created: i32,
}

/// One directory entry as the model described it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryConfig {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub created: i32,
    pub modified: i32,
    /// Permission bits (no file-type bits).
    pub permissions: u32,
    pub read_only: bool,
}

fn date_field(v: &Value, key: &str, default: i32) -> Result<i32> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::String(s)) => wire::date_from_text(s).with_context(|| key.to_string()),
        Some(Value::Number(n)) => n
            .as_i64()
            .map(wire::date_from_unix)
            .context("a date number is Unix seconds"),
        Some(other) => bail!("{key} is an RFC 3339 date, not {other}"),
    }
}

fn permissions_field(v: &Value, default: u32) -> Result<u32> {
    let mode = match v.get("permissions") {
        None | Some(Value::Null) => return Ok(default),
        Some(Value::String(s)) => {
            let s = s.trim().trim_start_matches("0o");
            ensure!(
                !s.is_empty() && s.len() <= 4 && s.chars().all(|c| ('0'..='7').contains(&c)),
                "permissions {s:?} is octal, like \"644\""
            );
            u32::from_str_radix(s, 8)?
        }
        Some(Value::Number(n)) => n.as_u64().context("permissions is a number")? as u32,
        Some(other) => bail!("permissions is an octal string like \"644\", not {other}"),
    };
    ensure!(mode <= 0o7777, "permissions {mode:o} is more than 12 bits");
    Ok(mode)
}

/// The volumes of a `volumes` startup parameter or an `afp_volumes` action.
pub fn volumes_from_json(v: &Value, now: i32) -> Result<Vec<VolumeConfig>> {
    let list = v
        .as_array()
        .context("volumes is a list of {\"name\"} objects")?;
    ensure!(
        list.len() <= wire::MAX_VOLUMES,
        "{} volumes; at most {}",
        list.len(),
        wire::MAX_VOLUMES
    );
    let mut out: Vec<VolumeConfig> = Vec::with_capacity(list.len());
    for (i, item) in list.iter().enumerate() {
        let name = match item {
            Value::String(s) => s.clone(),
            _ => item
                .get("name")
                .and_then(Value::as_str)
                .with_context(|| format!("volume {i} needs a name"))?
                .to_string(),
        };
        let name = wire::normalize(name.trim());
        wire::check_name(&name).with_context(|| format!("volume {i}"))?;
        ensure!(
            wire::mac_roman_encode(&name, 255).len() <= wire::MAX_VOLUME_NAME,
            "volume name {name:?} is longer than {} characters",
            wire::MAX_VOLUME_NAME
        );
        ensure!(
            !out.iter().any(|v| v.name.eq_ignore_ascii_case(&name)),
            "volume {name:?} is listed twice"
        );
        out.push(VolumeConfig {
            name,
            read_only: item
                .get("read_only")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            created: date_field(item, "created", now)?,
        });
    }
    Ok(out)
}

/// The entries of an `afp_directory_listing` action.
pub fn entries_from_json(v: &Value, now: i32) -> Result<Vec<EntryConfig>> {
    let list = v
        .get("entries")
        .and_then(Value::as_array)
        .context("afp_directory_listing needs \"entries\", a list ([] for an empty directory)")?;
    ensure!(
        list.len() <= MAX_DIR_ENTRIES,
        "{} entries; a listing holds at most {MAX_DIR_ENTRIES}",
        list.len()
    );
    let mut out: Vec<EntryConfig> = Vec::with_capacity(list.len());
    let mut seen = std::collections::HashSet::new();
    for (i, e) in list.iter().enumerate() {
        let name = wire::normalize(
            e.get("name")
                .and_then(Value::as_str)
                .with_context(|| format!("entry {i} needs a name"))?,
        );
        wire::check_name(&name).with_context(|| format!("entry {i}"))?;
        ensure!(seen.insert(name.clone()), "entry {name:?} is listed twice");
        let is_dir = match e.get("type").and_then(Value::as_str).unwrap_or("file") {
            "file" => false,
            "directory" | "dir" | "folder" => true,
            other => bail!("entry {name:?} has type {other:?}; use file or directory"),
        };
        let size = match e.get("size") {
            None | Some(Value::Null) => 0,
            Some(n) => n
                .as_u64()
                .with_context(|| format!("entry {name:?}: size is a byte count"))?,
        };
        ensure!(
            size <= MAX_FILE_BYTES as u64,
            "entry {name:?}: size {size} is more than {MAX_FILE_BYTES}"
        );
        let created = date_field(e, "created", now)?;
        out.push(EntryConfig {
            name,
            is_dir,
            size: if is_dir { 0 } else { size },
            created,
            modified: date_field(e, "modified", created)?,
            permissions: permissions_field(e, if is_dir { 0o755 } else { 0o644 })?,
            read_only: e.get("read_only").and_then(Value::as_bool).unwrap_or(false),
        });
    }
    Ok(out)
}

/// The bytes of an `afp_file_content` action.
pub fn content_from_json(v: &Value) -> Result<Vec<u8>> {
    let content = v
        .get("content")
        .and_then(Value::as_str)
        .context("afp_file_content needs \"content\", a string")?;
    let bytes = match v.get("encoding").and_then(Value::as_str).unwrap_or("utf8") {
        "utf8" | "utf-8" | "text" => content.as_bytes().to_vec(),
        "hex" => {
            let compact: String = content.chars().filter(|c| !c.is_whitespace()).collect();
            hex::decode(compact).context("content is not hex")?
        }
        other => bail!("encoding {other:?} is utf8 or hex"),
    };
    ensure!(
        bytes.len() <= MAX_FILE_BYTES,
        "{} bytes of content; at most {MAX_FILE_BYTES}",
        bytes.len()
    );
    Ok(bytes)
}

/// The AFP error an `afp_deny` action names.
pub fn deny_code(v: &Value) -> Result<i32> {
    Ok(
        match v
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("access_denied")
        {
            "access_denied" | "denied" => wire::err::ACCESS_DENIED,
            "not_found" => wire::err::OBJECT_NOT_FOUND,
            "exists" | "object_exists" => wire::err::OBJECT_EXISTS,
            "disk_full" => wire::err::DISK_FULL,
            "locked" => wire::err::OBJECT_LOCKED,
            "busy" => wire::err::FILE_BUSY,
            "misc" => wire::err::MISC_ERR,
            other => bail!(
                "error {other:?} is access_denied, not_found, exists, disk_full, locked, busy \
                 or misc"
            ),
        },
    )
}

/// Data the model sees for a write: text when it is UTF-8, hex otherwise.
pub fn data_for_model(bytes: &[u8]) -> (String, &'static str) {
    match std::str::from_utf8(bytes) {
        Ok(s) if !crate::utils::sanitize::has_controls(s.trim_end_matches(['\n', '\r', '\t'])) => {
            (s.to_string(), "utf8")
        }
        _ => (hex::encode(bytes), "hex"),
    }
}

impl Protocol for AfpProtocol {
    fn protocol_name(&self) -> &'static str {
        "AFP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>DSI>AFP"
    }
    fn description(&self) -> &'static str {
        "AFP (Apple Filing Protocol 3.x over DSI/TCP) file server: volumes, directory listings, file contents and every write decided by the LLM"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an AFP file server on port 548 with a Projects volume holding a README and a few design notes; refuse every write"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "afp",
            "apple filing protocol",
            "appleshare",
            "afp server",
            "afp over tcp",
            "netatalk",
            "apple file server",
            "data stream interface",
        ]
    }
    fn group_name(&self) -> &'static str {
        "File Sharing"
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(548))
            .well_known_port(548)
            // A model failure is answered with the AFP error the operation defines —
            // kFPMiscErr for a listing, a read or a volume list that cannot be produced,
            // kFPMiscErr for a write, create or delete nobody approved — never with an
            // invented listing or content, and never with success.
            .answers_on_failure()
            .request_only(
                "An AFP server only answers its client's requests; NetGet sends no \
                 DSIAttention (server messages, shutdown notices) and only DSITickle on its \
                 own",
            )
            .max_inbound_bytes(super::dsi::MAX_MESSAGE_LEN)
            .implementation(
                "Hand-written AFP 3.x over DSI (no Rust AFP crate exists): DSIOpenSession \
                 with a request quantum, DSIGetStatus, DSICommand, DSIWrite, DSITickle both \
                 ways, DSICloseSession; FPGetSrvrInfo, FPLogin and FPLoginExt with the No \
                 User Authent and Cleartxt Passwrd UAMs (the password is checked in Rust \
                 against the configured one and never reaches the model), FPLogout, \
                 FPGetSrvrParms, FPOpenVol, FPCloseVol, FPGetVolParms, FPGetFileDirParms, \
                 FPEnumerate, FPEnumerateExt, FPEnumerateExt2, FPOpenFork, FPRead, FPReadExt, \
                 FPGetForkParms, FPSetForkParms, FPWrite, FPWriteExt, FPFlushFork, FPFlush, \
                 FPCloseFork, FPCreateFile, FPCreateDir, FPDelete, FPResolveID and \
                 FPGetUserInfo; volume, file and directory bitmaps; MacRoman long names and \
                 decomposed UTF-8 names; AFP dates; NUL-separated paths with ascents; CNIDs \
                 stable for the server's lifetime",
            )
            .llm_control(
                "The volumes, every directory's entries (names, kinds, sizes, dates, \
                 permissions), every file's content, and whether each create, write, length \
                 change and delete is accepted",
            )
            .e2e_testing(
                "tests/server/afp: netatalk 4.6's test client afparg (C, netatalk's own AFP \
                 client library) logs in with Cleartxt Passwrd, walks a volume with \
                 FPEnumerate and FPResolveID, reads a file with FPOpenFork, FPGetForkParms and \
                 FPRead, and writes one with FPCreateFile, FPSetForkParms and FPWrite; \
                 asip-status (netatalk) decodes FPGetSrvrInfo; Nmap's afp NSE library (Lua, \
                 an independent client) runs afp-serverinfo, afp-showmount and afp-ls with No \
                 User Authent (FPGetSrvrParms, FPOpenVol, FPEnumerateExt2 with Unix \
                 privileges and dates); tshark's dsi and afp dissectors read both directions \
                 of those sessions. In-process: the password check, every bound and the \
                 fail-closed paths from a raw DSI client",
            )
            .notes(
                "Experimental: two independent clients drive it and tshark reads the bytes, \
                 but it is new, its fuzz target has not run at length, and its pair job had \
                 not run in CI when it landed. Not implemented, each answered \
                 kFPCallNotSupported: DHX, DHX2, DHCAST128 and Kerberos logins, FPLoginCont, \
                 byte-range locks, rename and move, FPCopyFile, FPExchangeFiles, catalog \
                 search, the desktop database (icons, comments, APPL), extended attributes, \
                 ACLs, Spotlight, FPSetFileDirParms and friends, FPMapID/FPMapName, session \
                 tokens and reconnect. Resource forks open empty and refuse writes. NetGet \
                 remembers what the model listed for the rest of a session; a new session asks \
                 again. Every failure logs decision=fail_closed_* and answers kFPMiscErr; a \
                 model refusal answers the error it named (decision=model_reject).",
            )
            .build()
    }

    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "server_name".into(),
                type_hint: "string".into(),
                description: "The name clients show for this server (FPGetSrvrInfo)".into(),
                required: false,
                example: json!("Studio"),
                default: Some(json!(DEFAULT_SERVER_NAME)),
            },
            ParameterDefinition {
                name: "volumes".into(),
                type_hint: "array".into(),
                description: format!(
                    "The volumes, fixed for every session ({{\"name\", \"read_only\"}}, at most \
                     {}). Without it the model is asked once per session (afp_list_volumes)",
                    wire::MAX_VOLUMES
                ),
                required: false,
                example: json!([{"name": "Projects"}, {"name": "Archive", "read_only": true}]),
                default: None,
            },
            ParameterDefinition {
                name: "username".into(),
                type_hint: "string".into(),
                description: "A user who may log in with Cleartxt Passwrd. Without it the \
                              server offers only guest access"
                    .into(),
                required: false,
                example: json!("alice"),
                default: None,
            },
            ParameterDefinition {
                name: "password".into(),
                type_hint: "string".into(),
                description: "The user's password (Cleartxt Passwrd compares the first 8 \
                              bytes, as AFP does). Checked by NetGet, never shown to the model"
                    .into(),
                required: false,
                example: json!("secret"),
                default: None,
            },
            ParameterDefinition {
                name: "guest_access".into(),
                type_hint: "boolean".into(),
                description: "Offer No User Authent (guest) logins".into(),
                required: false,
                example: json!(false),
                default: Some(json!(true)),
            },
            ParameterDefinition {
                name: "idle_timeout_secs".into(),
                type_hint: "number".into(),
                description: format!(
                    "Seconds a client may send nothing, not even a tickle, before its session \
                     is closed (1-{MAX_IDLE_TIMEOUT_SECS})"
                ),
                required: false,
                example: json!(600),
                default: Some(json!(DEFAULT_IDLE_TIMEOUT_SECS)),
            },
        ]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            volumes_action(),
            listing_action(),
            content_action(),
            allow_action(),
            deny_action(),
        ]
    }

    fn get_event_types(&self) -> Vec<EventType> {
        event_types()
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        let volumes = json!([{"name": "Projects"}]);
        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 548,
                "base_stack": "afp",
                "startup_params": {"volumes": volumes, "server_name": "Studio"},
                "instruction": "You are a design studio's file server. The Projects volume \
                                holds README.txt and a folder per client with a few notes \
                                each. Invent plausible text when a file is read. Refuse every \
                                create, write and delete."
            }),
            json!({
                "type": "open_server",
                "port": 548,
                "base_stack": "afp",
                "startup_params": {"volumes": volumes},
                "event_handlers": [{
                    "event_pattern": "*",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\nif t=='afp_list_directory':\n  a=[{'type':'afp_directory_listing','entries':[{'name':'README.txt','type':'file','size':6}] if e['path']=='' else []}]\nelif t=='afp_read_file':\n  a=[{'type':'afp_file_content','content':'hello\\n'}]\nelse:\n  a=[{'type':'afp_deny','error':'access_denied'}]\nprint(json.dumps({'actions':a}))"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 548,
                "base_stack": "afp",
                "startup_params": {"volumes": volumes},
                "event_handlers": [
                    {"event_pattern": "afp_list_directory", "handler": {"type": "static", "actions": [
                        {"type": "afp_directory_listing", "entries": [
                            {"name": "README.txt", "type": "file", "size": 6}
                        ]}
                    ]}},
                    {"event_pattern": "afp_read_file", "handler": {"type": "static", "actions": [
                        {"type": "afp_file_content", "content": "hello\n"}
                    ]}},
                    {"event_pattern": "*", "handler": {"type": "static", "actions": [
                        {"type": "afp_deny", "error": "access_denied"}
                    ]}}
                ]
            }),
        )
    }
}

impl Server for AfpProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            let params = ctx.startup_params.as_ref();
            let now = wire::now();
            let volumes = match params
                .map(|p| p.get_optional_array("volumes"))
                .transpose()?
            {
                Some(Some(list)) => Some(volumes_from_json(&Value::Array(list.clone()), now)?),
                _ => None,
            };
            let text = |key: &str| -> Result<Option<String>> {
                Ok(params
                    .map(|p| p.get_optional_string(key))
                    .transpose()?
                    .flatten())
            };
            let server_name = text("server_name")?.unwrap_or_else(|| DEFAULT_SERVER_NAME.into());
            ensure!(
                !server_name.is_empty() && server_name.len() <= 255,
                "server_name must be 1-255 bytes"
            );
            let username = text("username")?;
            let password = text("password")?;
            let credentials = match (username, password) {
                (Some(u), Some(p)) => {
                    ensure!(
                        !u.is_empty() && u.len() <= 255,
                        "username must be 1-255 bytes"
                    );
                    Some((u, p))
                }
                (None, None) => None,
                _ => bail!("username and password go together"),
            };
            let guest = params
                .map(|p| p.get_optional_bool("guest_access"))
                .transpose()?
                .flatten()
                .unwrap_or(true);
            ensure!(
                guest || credentials.is_some(),
                "with guest_access false a username and password are needed, or nobody can \
                 log in"
            );
            let idle = params
                .map(|p| p.get_optional_u64("idle_timeout_secs"))
                .transpose()?
                .flatten()
                .unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS);
            ensure!(
                (1..=MAX_IDLE_TIMEOUT_SECS).contains(&idle),
                "idle_timeout_secs must be between 1 and {MAX_IDLE_TIMEOUT_SECS}, got {idle}"
            );
            super::AfpServer::spawn(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                super::Config {
                    server_name,
                    volumes,
                    credentials,
                    guest,
                    idle: std::time::Duration::from_secs(idle),
                },
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let kind = action
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("Missing 'type' field in action"))?;
        let custom = |name: &str| ActionResult::Custom {
            name: name.to_string(),
            data: action.clone(),
        };
        match kind {
            "afp_volumes" => {
                volumes_from_json(
                    action
                        .get("volumes")
                        .context("afp_volumes needs \"volumes\", a list")?,
                    0,
                )?;
                Ok(custom(RESULT_VOLUMES))
            }
            "afp_directory_listing" => {
                entries_from_json(&action, 0)?;
                Ok(custom(RESULT_LISTING))
            }
            "afp_file_content" => {
                content_from_json(&action)?;
                Ok(custom(RESULT_CONTENT))
            }
            "afp_allow" => Ok(custom(RESULT_ALLOW)),
            "afp_deny" => {
                deny_code(&action)?;
                Ok(custom(RESULT_DENY))
            }
            other => Err(anyhow!(
                "Unknown AFP action '{other}'. Valid actions: afp_volumes, \
                 afp_directory_listing, afp_file_content, afp_allow, afp_deny"
            )),
        }
    }
}

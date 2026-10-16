//! AFP client actions, events and metadata.
//!
//! NetGet connects to an AFP file server (netatalk, an old Mac), asks it about itself
//! (FPGetSrvrInfo), opens a DSI session and logs in — with the configured user name and
//! password over Cleartxt Passwrd, or as a guest — and then does what the model asks: list the
//! volumes, list a directory, read a file, write one, create a directory, delete something.
//! Every byte is the shared codec's (`src/server/afp/wire.rs`, `dsi.rs`); the model works in
//! volume names and '/'-separated paths, and never sees the password.
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::afp::wire;
use crate::state::app_state::AppState;
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

/// The name of the `ClientActionResult::Custom` every operation travels as.
pub const OPERATION_RESULT: &str = "afp_operation";

/// How long the server has to answer one request.
pub const DEFAULT_RESPONSE_TIMEOUT_MS: u64 = 10_000;
pub const MIN_RESPONSE_TIMEOUT_MS: u64 = 100;
pub const MAX_RESPONSE_TIMEOUT_MS: u64 = 120_000;
/// The most bytes one `afp_read_file` reads, by default and at most.
pub const DEFAULT_READ_BYTES: u64 = 1024 * 1024;
pub const MAX_READ_BYTES: u64 = 16 * 1024 * 1024;
/// The most bytes one `afp_write_file` writes.
pub const MAX_WRITE_BYTES: usize = 16 * 1024 * 1024;
/// The most entries one `afp_list_directory` reports.
pub const MAX_LIST_ENTRIES: usize = 4096;

#[derive(Default)]
pub struct AfpClientProtocol;

impl AfpClientProtocol {
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

fn volume_p() -> Parameter {
    p(
        "volume",
        "string",
        "The volume's name, as afp_list_volumes reported it",
        true,
    )
}

fn path_p(what: &str) -> Parameter {
    p(
        "path",
        "string",
        &format!("{what}, '/'-separated from the volume's root (\"\" is the root)"),
        true,
    )
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
        log_template: Some(
            LogTemplate::new()
                .with_info(format!("-> AFP {}", name.trim_start_matches("afp_")))
                .with_debug(format!("AFP {name}: {{json(.)}}")),
        ),
    }
}

pub fn all_actions() -> Vec<ActionDefinition> {
    vec![
        action(
            "afp_list_volumes",
            "List the server's volumes (FPGetSrvrParms); the answer arrives as afp_volumes",
            vec![],
            json!({"type": "afp_list_volumes"}),
        ),
        action(
            "afp_list_directory",
            "List a directory (FPOpenVol, then FPEnumerateExt2 until the server has no more); \
             the answer arrives as afp_directory",
            vec![volume_p(), path_p("The directory")],
            json!({"type": "afp_list_directory", "volume": "Share", "path": ""}),
        ),
        action(
            "afp_read_file",
            "Read a file's data fork (FPOpenFork, FPReadExt, FPCloseFork); the content arrives \
             as afp_file",
            vec![
                volume_p(),
                path_p("The file"),
                p(
                    "max_bytes",
                    "number",
                    &format!(
                        "Read at most this many bytes (default {DEFAULT_READ_BYTES}, at most \
                         {MAX_READ_BYTES})"
                    ),
                    false,
                ),
            ],
            json!({"type": "afp_read_file", "volume": "Share", "path": "notes/todo.txt"}),
        ),
        action(
            "afp_write_file",
            "Create a file if it is missing and replace its content (FPCreateFile, FPOpenFork, \
             FPSetForkParms to empty it, FPWriteExt, FPCloseFork); the result arrives as \
             afp_done",
            vec![
                volume_p(),
                path_p("The file"),
                p("content", "string", "The file's new content (text, or hex with encoding hex)", true),
                p(
                    "encoding",
                    "string",
                    "utf8 (the default: content is the text itself) or hex",
                    false,
                ),
            ],
            json!({"type": "afp_write_file", "volume": "Share", "path": "hello.txt", "content": "hello\n"}),
        ),
        action(
            "afp_create_directory",
            "Create a directory (FPCreateDir); the result arrives as afp_done",
            vec![volume_p(), path_p("The new directory")],
            json!({"type": "afp_create_directory", "volume": "Share", "path": "reports"}),
        ),
        action(
            "afp_delete",
            "Delete a file or an empty directory (FPDelete); the result arrives as afp_done",
            vec![volume_p(), path_p("The item")],
            json!({"type": "afp_delete", "volume": "Share", "path": "old.txt"}),
        ),
        action(
            "afp_get_info",
            "Read one item's parameters (FPGetFileDirParms); the answer arrives as afp_info",
            vec![volume_p(), path_p("The item")],
            json!({"type": "afp_get_info", "volume": "Share", "path": "notes"}),
        ),
        action(
            "disconnect",
            "Log out (FPLogout), close the DSI session and the connection",
            vec![],
            json!({"type": "disconnect"}),
        ),
    ]
}

fn ev(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, json!({"type": "afp_list_volumes"}))
        .with_parameters(params)
        .with_actions(all_actions())
        .with_log_template(
            LogTemplate::new()
                .with_info(format!("AFP {id}"))
                .with_debug(format!("AFP {id}: {{json(.)}}")),
        )
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "afp_connected",
        "Connected and logged in to the AFP server",
        vec![
            p(
                "server",
                "object",
                "What FPGetSrvrInfo said: name, machine_type, versions, uams, addresses",
                true,
            ),
            p(
                "user",
                "string",
                "Who NetGet logged in as (\"guest\" for No User Authent)",
                true,
            ),
            p("uam", "string", "The login method: No User Authent or Cleartxt Passwrd", true),
            p("version", "string", "The AFP version agreed", true),
        ],
    )
});

pub static VOLUMES_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "afp_volumes",
        "The server's volumes",
        vec![p(
            "volumes",
            "array",
            "Each volume's name and whether it has a password",
            true,
        )],
    )
});

pub static DIRECTORY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "afp_directory",
        "A directory's entries",
        vec![
            volume_p(),
            path_p("The directory"),
            p(
                "entries",
                "array",
                "Each entry: name, type (file or directory), size, created, modified, id, \
                 permissions (octal), offspring (directories)",
                true,
            ),
            p(
                "truncated",
                "boolean",
                "True when the directory held more than NetGet reports",
                false,
            ),
        ],
    )
});

pub static FILE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "afp_file",
        "A file's content",
        vec![
            volume_p(),
            path_p("The file"),
            p("size", "number", "The file's size in bytes", true),
            p("content", "string", "The bytes read, as text or as hex (see encoding)", true),
            p(
                "encoding",
                "string",
                "utf8 (text) or hex (bytes that are not text)",
                true,
            ),
            p(
                "truncated",
                "boolean",
                "True when the file is longer than what was read",
                false,
            ),
        ],
    )
});

pub static INFO_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "afp_info",
        "One item's parameters",
        vec![
            volume_p(),
            path_p("The item"),
            p(
                "item",
                "object",
                "name, type, size, created, modified, id, permissions",
                true,
            ),
        ],
    )
});

pub static DONE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "afp_done",
        "A write, a directory creation or a delete succeeded",
        vec![
            p(
                "operation",
                "string",
                "afp_write_file, afp_create_directory or afp_delete",
                true,
            ),
            volume_p(),
            path_p("The item"),
            p("bytes_written", "number", "How many bytes a write put in the file", false),
        ],
    )
});

pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "afp_error",
        "The server refused an operation, or answered something NetGet cannot read",
        vec![
            p("operation", "string", "The action that failed", true),
            p("volume", "string", "The volume, when there was one", false),
            p("path", "string", "The path, when there was one", false),
            p("code", "number", "The AFP result code (e.g. -5000)", false),
            p("error", "string", "Its name (kFPAccessDenied …)", false),
            p("message", "string", "What the server refused, or what could not be read", true),
        ],
    )
});

/// One thing the model asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    ListVolumes,
    ListDirectory {
        volume: String,
        path: Vec<String>,
    },
    Read {
        volume: String,
        path: Vec<String>,
        max_bytes: u64,
    },
    Write {
        volume: String,
        path: Vec<String>,
        data: Vec<u8>,
    },
    CreateDirectory {
        volume: String,
        path: Vec<String>,
    },
    Delete {
        volume: String,
        path: Vec<String>,
    },
    Info {
        volume: String,
        path: Vec<String>,
    },
}

impl Operation {
    pub fn name(&self) -> &'static str {
        match self {
            Operation::ListVolumes => "afp_list_volumes",
            Operation::ListDirectory { .. } => "afp_list_directory",
            Operation::Read { .. } => "afp_read_file",
            Operation::Write { .. } => "afp_write_file",
            Operation::CreateDirectory { .. } => "afp_create_directory",
            Operation::Delete { .. } => "afp_delete",
            Operation::Info { .. } => "afp_get_info",
        }
    }

    /// The volume and path for events, when the operation has them.
    pub fn target(&self) -> (Option<&str>, Option<String>) {
        match self {
            Operation::ListVolumes => (None, None),
            Operation::ListDirectory { volume, path }
            | Operation::Read { volume, path, .. }
            | Operation::Write { volume, path, .. }
            | Operation::CreateDirectory { volume, path }
            | Operation::Delete { volume, path }
            | Operation::Info { volume, path } => (Some(volume), Some(path.join("/"))),
        }
    }
}

fn volume(v: &Value) -> Result<String> {
    let name = v
        .get("volume")
        .and_then(Value::as_str)
        .context("needs \"volume\", the volume's name")?
        .trim();
    wire::check_name(name).context("volume")?;
    Ok(wire::normalize(name))
}

/// A '/'-separated path into its names; empty components are dropped.
pub fn split_path(s: &str) -> Result<Vec<String>> {
    let parts: Vec<String> = s
        .split('/')
        .filter(|p| !p.is_empty())
        .map(wire::normalize)
        .collect();
    ensure!(
        parts.len() <= wire::MAX_PATH_ELEMENTS,
        "a path of more than {} elements",
        wire::MAX_PATH_ELEMENTS
    );
    for part in &parts {
        wire::check_name(part)?;
    }
    Ok(parts)
}

fn path(v: &Value, required_nonempty: bool) -> Result<Vec<String>> {
    let s = match v.get("path") {
        None | Some(Value::Null) => "",
        Some(Value::String(s)) => s.as_str(),
        Some(other) => bail!("path is a string, not {other}"),
    };
    let parts = split_path(s)?;
    ensure!(
        !required_nonempty || !parts.is_empty(),
        "path must name an item, not the volume's root"
    );
    Ok(parts)
}

/// Validate an action into its operation; `None` for `disconnect`.
pub fn operation_from_action(v: &Value) -> Result<Option<Operation>> {
    let kind = v
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("Missing 'type' field in action"))?;
    Ok(Some(match kind {
        "afp_list_volumes" => Operation::ListVolumes,
        "afp_list_directory" => Operation::ListDirectory {
            volume: volume(v)?,
            path: path(v, false)?,
        },
        "afp_read_file" => {
            let max_bytes = match v.get("max_bytes") {
                None | Some(Value::Null) => DEFAULT_READ_BYTES,
                Some(n) => n.as_u64().context("max_bytes is a byte count")?,
            };
            ensure!(
                (1..=MAX_READ_BYTES).contains(&max_bytes),
                "max_bytes must be between 1 and {MAX_READ_BYTES}"
            );
            Operation::Read {
                volume: volume(v)?,
                path: path(v, true)?,
                max_bytes,
            }
        }
        "afp_write_file" => {
            let content = v
                .get("content")
                .and_then(Value::as_str)
                .context("afp_write_file needs \"content\", a string")?;
            let data = match v.get("encoding").and_then(Value::as_str).unwrap_or("utf8") {
                "utf8" | "utf-8" | "text" => content.as_bytes().to_vec(),
                "hex" => {
                    let compact: String = content.chars().filter(|c| !c.is_whitespace()).collect();
                    hex::decode(compact).context("content is not hex")?
                }
                other => bail!("encoding {other:?} is utf8 or hex"),
            };
            ensure!(
                data.len() <= MAX_WRITE_BYTES,
                "{} bytes; one write carries at most {MAX_WRITE_BYTES}",
                data.len()
            );
            Operation::Write {
                volume: volume(v)?,
                path: path(v, true)?,
                data,
            }
        }
        "afp_create_directory" => Operation::CreateDirectory {
            volume: volume(v)?,
            path: path(v, true)?,
        },
        "afp_delete" => Operation::Delete {
            volume: volume(v)?,
            path: path(v, true)?,
        },
        "afp_get_info" => Operation::Info {
            volume: volume(v)?,
            path: path(v, false)?,
        },
        "disconnect" => return Ok(None),
        other => bail!(
            "Unknown AFP client action '{other}'. Valid actions: afp_list_volumes, \
             afp_list_directory, afp_read_file, afp_write_file, afp_create_directory, \
             afp_delete, afp_get_info, disconnect"
        ),
    }))
}

impl Protocol for AfpClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "AFP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>DSI>AFP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "afp",
            "apple filing protocol",
            "appleshare",
            "afp client",
            "afp over tcp",
            "netatalk",
            "apple file server",
        ]
    }
    fn description(&self) -> &'static str {
        "AFP (Apple Filing Protocol 3.x over DSI/TCP) client: logs in to a Mac or netatalk file server, lists volumes and directories, reads and writes files as the LLM decides"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the AFP server at 192.168.1.20:548 as a guest, list its volumes and read every text file at the top of the first one"
    }
    fn group_name(&self) -> &'static str {
        "File Sharing"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        all_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        all_actions()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            VOLUMES_EVENT.clone(),
            DIRECTORY_EVENT.clone(),
            FILE_EVENT.clone(),
            INFO_EVENT.clone(),
            DONE_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "username".into(),
                type_hint: "string".into(),
                description: "Log in as this user with Cleartxt Passwrd. Without it NetGet \
                              logs in as a guest (No User Authent)"
                    .into(),
                required: false,
                example: json!("alice"),
                default: None,
            },
            ParameterDefinition {
                name: "password".into(),
                type_hint: "string".into(),
                description: "The user's password (Cleartxt Passwrd sends at most 8 bytes, \
                              unencrypted). Never shown to the model"
                    .into(),
                required: false,
                example: json!("secret"),
                default: None,
            },
            ParameterDefinition {
                name: "response_timeout_ms".into(),
                type_hint: "number".into(),
                description: format!(
                    "How long the server has to answer one request, in milliseconds \
                     ({MIN_RESPONSE_TIMEOUT_MS}-{MAX_RESPONSE_TIMEOUT_MS})"
                ),
                required: false,
                example: json!(5000),
                default: Some(json!(DEFAULT_RESPONSE_TIMEOUT_MS)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "Hand-written AFP 3.x client over DSI sharing the server's codec \
                 (src/server/afp/wire.rs, dsi.rs): DSIGetStatus on a connection of its own \
                 (FPGetSrvrInfo), DSIOpenSession, FPLogin with Cleartxt Passwrd or No User \
                 Authent at the highest AFP 3 version both sides speak, FPGetSrvrParms, \
                 FPOpenVol, FPEnumerateExt2 paged to the end, FPGetFileDirParms, FPOpenFork, \
                 FPReadExt, FPCreateFile, FPSetForkParms, FPWriteExt in quantum-sized chunks, \
                 FPCloseFork, FPCreateDir, FPDelete, FPLogout and DSICloseSession; DSITickle \
                 every 30 s while idle. One request on the wire at a time; the model is asked \
                 from a separate task",
            )
            .llm_control(
                "Which volumes and directories to list, which files to read, and what to \
                 write, create and delete; every answer arrives as a decoded event. The login \
                 is the configured user's (or a guest's) and the password never reaches the \
                 model",
            )
            .e2e_testing(
                "tests/client/afp: netatalk 4.6's afpd (an independent C server, run \
                 unprivileged in a temporary directory with a guest volume) — NetGet lists the \
                 volumes, lists a directory and reads a file whose bytes the test placed on \
                 disk, writes a file the test then reads from disk, creates a directory and \
                 deletes a file, each asserted on disk. Against NetGet's own server as a \
                 regression only: Cleartxt Passwrd, refusals, bounds and the follow-up depth",
            )
            .notes(
                "Experimental: one independent server (netatalk), guest login only against \
                 it (cleartext needs a PAM account), and its pair job had not run in CI when \
                 it landed. No DHX/DHX2 logins, no resource forks, no rename, no reconnect; \
                 server attention messages are read and ignored.",
            )
            .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({
            "type": "open_client",
            "protocol": "AFP",
            "remote_addr": "127.0.0.1:548",
            "instruction": "List the volumes, then list the root of the first one and read README.txt"
        });
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "afp_connected", "handler": {"type": "static", "actions": [{"type": "afp_list_volumes"}]}},
            {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{
            "event_pattern": "*",
            "handler": {"type": "script", "language": "python",
                "code": "import json,sys\ni=json.load(sys.stdin); t=i['event_type_id']; e=i['event']\na=[]\nif t=='afp_connected': a=[{'type':'afp_list_volumes'}]\nelif t=='afp_volumes' and e['volumes']: a=[{'type':'afp_list_directory','volume':e['volumes'][0]['name'],'path':''}]\nprint(json.dumps({'actions':a}))"}
        }]);
        StartupExamples::new(llm, scripted, static_example)
    }
}

impl Client for AfpClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(async move {
            let params = ctx.startup_params.as_ref();
            let text = |key: &str| -> Result<Option<String>> {
                Ok(params
                    .map(|p| p.get_optional_string(key))
                    .transpose()?
                    .flatten())
            };
            let credentials = match (text("username")?, text("password")?) {
                (Some(u), Some(p)) => Some((u, p)),
                (None, None) => None,
                _ => bail!("username and password go together"),
            };
            let timeout = params
                .map(|p| p.get_optional_u64("response_timeout_ms"))
                .transpose()?
                .flatten()
                .unwrap_or(DEFAULT_RESPONSE_TIMEOUT_MS);
            ensure!(
                (MIN_RESPONSE_TIMEOUT_MS..=MAX_RESPONSE_TIMEOUT_MS).contains(&timeout),
                "response_timeout_ms must be between {MIN_RESPONSE_TIMEOUT_MS} and \
                 {MAX_RESPONSE_TIMEOUT_MS}, got {timeout}"
            );
            super::AfpClient::connect(
                ctx.remote_addr,
                credentials,
                std::time::Duration::from_millis(timeout),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match operation_from_action(&action)? {
            None => Ok(ClientActionResult::Disconnect),
            Some(_) => Ok(ClientActionResult::Custom {
                name: OPERATION_RESULT.to_string(),
                data: action,
            }),
        }
    }
}

/// Validate an action into its operation, for the transport.
pub fn require_operation(v: &Value) -> Result<Operation> {
    operation_from_action(v)?.ok_or_else(|| anyhow!("disconnect is not an operation"))
}

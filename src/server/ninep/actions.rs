use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct NinepProtocol;
impl NinepProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub fn parameter(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}

pub fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
) -> ActionDefinition {
    let log_template = match name {
        "ninep_entry" => LogTemplate::new().with_info("-> 9P entry {kind} size={size}"),
        "ninep_listing" => LogTemplate::new().with_info("-> 9P listing {preview(entries,120)}"),
        "ninep_content" => LogTemplate::new().with_info("-> 9P content {preview(data,80)}"),
        "ninep_error" => LogTemplate::new().with_info("-> 9P error {message}"),
        _ => LogTemplate::new().with_info(format!("-> 9P {name}")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}

fn entry_action() -> ActionDefinition {
    action(
        "ninep_entry",
        "Say that the path exists and what it is. Rust builds the qid and stat from these fields.",
        vec![
            parameter("kind", "string", "What the path is: file or dir", true),
            parameter(
                "size",
                "number",
                "File length in bytes (0 for a directory)",
                false,
            ),
            parameter(
                "mode",
                "number",
                "Permission bits, e.g. 420 (0644) for a file or 493 (0755) for a directory",
                false,
            ),
            parameter("mtime", "number", "Modification time, Unix seconds", false),
            parameter(
                "owner",
                "string",
                "Owner and group name shown in listings, default netget",
                false,
            ),
        ],
        json!({"type":"ninep_entry","kind":"file","size":12}),
    )
}

fn not_found_action() -> ActionDefinition {
    action(
        "ninep_not_found",
        "Say that nothing exists at this path; the client gets 'file does not exist'.",
        vec![],
        json!({"type":"ninep_not_found"}),
    )
}

fn listing_action() -> ActionDefinition {
    action(
        "ninep_listing",
        "List a directory's entries. Rust encodes them as stat entries and pages them to the client.",
        vec![parameter(
            "entries",
            "array",
            "At most 1024 entries: [{name, kind: file|dir, size?, mode?, mtime?, owner?}]",
            true,
        )],
        json!({"type":"ninep_listing","entries":[{"name":"readme.txt","kind":"file","size":12},{"name":"docs","kind":"dir"}]}),
    )
}

fn content_action() -> ActionDefinition {
    action(
        "ninep_content",
        "Supply a file's whole content (at most 1 MiB). Rust serves each read from it at the client's offset.",
        vec![
            parameter("data", "string", "The file content", true),
            parameter("encoding", "string", "utf8 (default) or hex for binary content", false),
        ],
        json!({"type":"ninep_content","data":"hello world\n"}),
    )
}

fn ok_action() -> ActionDefinition {
    action(
        "ninep_ok",
        "Accept the change (a write, create, remove or stat change); the client is told it succeeded.",
        vec![],
        json!({"type":"ninep_ok"}),
    )
}

fn error_action() -> ActionDefinition {
    action(
        "ninep_error",
        "Refuse the request with an error string the client shows, e.g. 'permission denied'.",
        vec![parameter(
            "message",
            "string",
            "Error text, at most 255 bytes",
            true,
        )],
        json!({"type":"ninep_error","message":"permission denied"}),
    )
}

fn path_param() -> Parameter {
    parameter(
        "path",
        "string",
        "Absolute path, e.g. /docs/readme.txt",
        true,
    )
}

fn uname_param() -> Parameter {
    parameter("uname", "string", "User name the client attached as", true)
}

pub static STAT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ninep_stat",
        "The client walked to or asked about a path; say whether it exists and what it is.",
        entry_action().example.clone(),
    )
    .with_parameters(vec![path_param(), uname_param()])
    .with_actions(vec![entry_action(), not_found_action(), error_action()])
});

pub static LIST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ninep_list",
        "The client is reading a directory; list its entries.",
        listing_action().example.clone(),
    )
    .with_parameters(vec![path_param(), uname_param()])
    .with_actions(vec![listing_action(), error_action()])
});

pub static READ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ninep_read",
        "The client is reading a file from its start; supply the whole content.",
        content_action().example.clone(),
    )
    .with_parameters(vec![path_param(), uname_param()])
    .with_actions(vec![content_action(), error_action()])
});

pub static WRITE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ninep_write",
        "The client wrote bytes into a file at an offset; accept or refuse them.",
        ok_action().example.clone(),
    )
    .with_parameters(vec![
        path_param(),
        parameter("offset", "number", "Byte offset of the write", true),
        parameter("data", "string", "The bytes written, as text", true),
        parameter(
            "encoding",
            "string",
            "utf8, or hex when the bytes are not UTF-8",
            true,
        ),
        uname_param(),
    ])
    .with_actions(vec![ok_action(), error_action()])
});

pub static CREATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ninep_create",
        "The client is creating a file or directory; accept or refuse.",
        ok_action().example.clone(),
    )
    .with_parameters(vec![
        path_param(),
        parameter("kind", "string", "What the path is: file or dir", true),
        parameter("mode", "number", "Permission bits requested", true),
        uname_param(),
    ])
    .with_actions(vec![ok_action(), error_action()])
});

pub static REMOVE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ninep_remove",
        "The client is removing a file or directory; accept or refuse.",
        ok_action().example.clone(),
    )
    .with_parameters(vec![path_param(), uname_param()])
    .with_actions(vec![ok_action(), error_action()])
});

pub static WSTAT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ninep_wstat",
        "The client is renaming, truncating or changing the mode of a path; accept or refuse.",
        ok_action().example.clone(),
    )
    .with_parameters(vec![
        path_param(),
        parameter(
            "name",
            "string",
            "New name in the same directory, when renaming",
            false,
        ),
        parameter(
            "length",
            "number",
            "New length, when truncating (0 for OTRUNC)",
            false,
        ),
        parameter(
            "mode",
            "number",
            "New permission bits, when changing them",
            false,
        ),
        uname_param(),
    ])
    .with_actions(vec![ok_action(), error_action()])
});

/// Validate one listing or stat entry; also used for the listing's elements.
pub fn check_entry(v: &Value, named: bool) -> Result<()> {
    ensure!(
        matches!(v["kind"].as_str(), Some("file" | "dir")),
        "kind must be file or dir"
    );
    if named {
        let name = v["name"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("each entry needs a name"))?;
        super::wire::check_name(name)?;
        ensure!(name != "..", "a listing cannot contain ..");
    }
    for key in ["size", "mode", "mtime"] {
        ensure!(
            v.get(key).is_none_or(Value::is_u64),
            "{key} must be a non-negative integer"
        );
    }
    ensure!(
        v["mode"].as_u64().is_none_or(|m| m <= 0o777),
        "mode holds permission bits only (at most 0777)"
    );
    ensure!(
        v["mtime"].as_u64().is_none_or(|m| m <= u64::from(u32::MAX)),
        "mtime must fit 32 bits"
    );
    ensure!(
        v.get("owner")
            .is_none_or(|o| o.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 64)),
        "owner must be 1 to 64 bytes"
    );
    Ok(())
}

impl Protocol for NinepProtocol {
    fn protocol_name(&self) -> &'static str {
        "9P"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>9P"
    }
    fn description(&self) -> &'static str {
        "9P2000 file server (Plan 9's file protocol) whose files and directories the handler supplies"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["9p", "9p2000", "plan 9", "styx", "ninep"]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            entry_action(),
            not_found_action(),
            listing_action(),
            content_action(),
            ok_action(),
            error_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            STAT_EVENT.clone(),
            LIST_EVENT.clone(),
            READ_EVENT.clone(),
            WRITE_EVENT.clone(),
            CREATE_EVENT.clone(),
            REMOVE_EVENT.clone(),
            WSTAT_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "idle_timeout_secs".into(),
            type_hint: "number".into(),
            description: "Seconds a connection may stay silent between messages (1..=86400)".into(),
            required: false,
            example: json!(600),
            default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(564))
            .well_known_port(564)
            .implementation("9P2000 over Tokio TCP, hand-written: version, attach (no auth), walk with partial results and .., open/create/read/write/clunk/remove/stat/wstat, flush, directory reads paged as whole stat entries")
            .llm_control("Whether each path exists and what it is, directory listings, file contents, and whether each write, create, remove, rename or truncate is accepted")
            .e2e_testing("tests/server/ninep: raw messages and bounds; 9fans.net/go's plan9/client and knusbaum/go9p's client (Go) as independent clients")
            .notes("9P2000 only: a 9P2000.u or 9P2000.L client is offered plain 9P2000 and Linux's v9fs will refuse it. No authentication (Tauth is refused, every attach succeeds); uname is passed to the handler. Nothing is stored: a file's content is asked for on each read from offset 0 and served from that answer for the rest of the fid's reads. msize at most 65536, 256 fids per connection, 16 elements per walk, 1 MiB per file, 1024 entries per directory. A handler failure answers Rerror with a generic message, never a fabricated file.")
            .request_only("Every reply answers the T-message with the same tag; the server never speaks first")
            .answers_on_failure()
            .max_inbound_bytes(super::wire::MAX_MSIZE as usize)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "9P file server on port 5640 exporting a docs directory with a readme"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"9p","port":5640,"instruction":"Export /docs containing readme.txt with a short welcome text; refuse writes"});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([
            {"event_pattern":"ninep_stat","handler":{"type":"script","language":"python","code":"import json,sys\np=json.load(sys.stdin)['event']['path']\nt={'/docs':{'type':'ninep_entry','kind':'dir'},'/docs/readme.txt':{'type':'ninep_entry','kind':'file','size':8}}\nprint(json.dumps({'actions':[t.get(p,{'type':'ninep_not_found'})]}))"}},
            {"event_pattern":"ninep_list","handler":{"type":"script","language":"python","code":"import json,sys\np=json.load(sys.stdin)['event']['path']\ne=[{'name':'docs','kind':'dir'}] if p=='/' else [{'name':'readme.txt','kind':'file','size':8}]\nprint(json.dumps({'actions':[{'type':'ninep_listing','entries':e}]}))"}},
            {"event_pattern":"ninep_read","handler":{"type":"static","actions":[{"type":"ninep_content","data":"welcome\n"}]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[{"type":"ninep_error","message":"permission denied"}]}}
        ]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"ninep_stat","handler":{"type":"static","actions":[{"type":"ninep_entry","kind":"file","size":6}]}},
            {"event_pattern":"ninep_list","handler":{"type":"static","actions":[{"type":"ninep_listing","entries":[{"name":"hello","kind":"file","size":6}]}]}},
            {"event_pattern":"ninep_read","handler":{"type":"static","actions":[{"type":"ninep_content","data":"hello\n"}]}},
            {"event_pattern":"*","handler":{"type":"static","actions":[{"type":"ninep_error","message":"read-only file system"}]}}
        ]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Server for NinepProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        match name.as_str() {
            "ninep_entry" => check_entry(&v, false)?,
            "ninep_listing" => {
                let entries = v["entries"]
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("entries must be an array"))?;
                ensure!(
                    entries.len() <= super::wire::MAX_ENTRIES,
                    "a listing holds at most {} entries",
                    super::wire::MAX_ENTRIES
                );
                for e in entries {
                    check_entry(e, true)?;
                }
            }
            "ninep_content" => {
                let data = v["data"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("data must be a string"))?;
                let bytes = super::wire::from_text(data, v["encoding"].as_str())?;
                ensure!(
                    bytes.len() <= super::wire::MAX_CONTENT,
                    "content exceeds {} bytes",
                    super::wire::MAX_CONTENT
                );
            }
            "ninep_error" => {
                let message = v["message"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("message must be a string"))?;
                ensure!(
                    !message.is_empty() && message.len() <= 255,
                    "message must be 1 to 255 bytes"
                );
            }
            "ninep_not_found" | "ninep_ok" => {}
            _ => bail!("Unknown 9P server action"),
        }
        Ok(ActionResult::Custom { name, data: v })
    }
}

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::ninep::{
    actions::{action, parameter},
    wire,
};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct NinepClientProtocol;
impl NinepClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn path_param() -> crate::llm::actions::Parameter {
    parameter(
        "path",
        "string",
        "Absolute path on the server, e.g. /docs/readme.txt",
        true,
    )
}

fn ls_action() -> ActionDefinition {
    action(
        "ninep_ls",
        "List a directory; the entries arrive in ninep_result.",
        vec![path_param()],
        json!({"type":"ninep_ls","path":"/"}),
    )
}

fn cat_action() -> ActionDefinition {
    action(
        "ninep_cat",
        "Read a whole file (at most 1 MiB); the content arrives in ninep_result.",
        vec![path_param()],
        json!({"type":"ninep_cat","path":"/docs/readme.txt"}),
    )
}

fn write_action() -> ActionDefinition {
    action(
        "ninep_write",
        "Write a file: replace its content, or append to it; create it first when create is true.",
        vec![
            path_param(),
            parameter("data", "string", "Content to write", true),
            parameter("encoding", "string", "utf8 (default) or hex", false),
            parameter(
                "append",
                "boolean",
                "Append after the current end instead of replacing",
                false,
            ),
            parameter(
                "create",
                "boolean",
                "Create the file when it does not exist",
                false,
            ),
        ],
        json!({"type":"ninep_write","path":"/notes.txt","data":"hello\n","create":true}),
    )
}

fn stat_action() -> ActionDefinition {
    action(
        "ninep_stat",
        "Read a path's stat (kind, size, mode, owner, mtime).",
        vec![path_param()],
        json!({"type":"ninep_stat","path":"/docs"}),
    )
}

fn mkdir_action() -> ActionDefinition {
    action(
        "ninep_mkdir",
        "Create a directory at the path.",
        vec![path_param()],
        json!({"type":"ninep_mkdir","path":"/new"}),
    )
}

fn remove_action() -> ActionDefinition {
    action(
        "ninep_remove",
        "Remove a file or an empty directory.",
        vec![path_param()],
        json!({"type":"ninep_remove","path":"/notes.txt"}),
    )
}

fn rename_action() -> ActionDefinition {
    action(
        "ninep_rename",
        "Rename a path within its directory (9P cannot move between directories).",
        vec![
            path_param(),
            parameter("name", "string", "New name, without a directory", true),
        ],
        json!({"type":"ninep_rename","path":"/notes.txt","name":"old-notes.txt"}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Clunk everything and close the 9P connection",
        vec![],
        json!({"type":"disconnect"}),
    )
}

fn actions() -> Vec<ActionDefinition> {
    vec![
        ls_action(),
        cat_action(),
        write_action(),
        stat_action(),
        mkdir_action(),
        remove_action(),
        rename_action(),
        disconnect_action(),
    ]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ninep_connected",
        "Attached to the 9P server's root; ready for file operations.",
        ls_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "version",
            "string",
            "Protocol version the server agreed to",
            true,
        ),
        parameter("msize", "number", "Negotiated maximum message size", true),
        parameter("uname", "string", "User name attached as", true),
    ])
    .with_actions(actions())
});

pub static RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ninep_result",
        "The outcome of one file operation.",
        cat_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "op",
            "string",
            "ls, cat, write, stat, mkdir, remove or rename",
            true,
        ),
        path_param(),
        parameter(
            "ok",
            "boolean",
            "Whether the server accepted the operation",
            true,
        ),
        parameter(
            "error",
            "string",
            "The server's error text when ok is false",
            false,
        ),
        parameter(
            "entries",
            "array",
            "For ls: [{name, kind, size, mode, owner, mtime}]",
            false,
        ),
        parameter("data", "string", "For cat: the content", false),
        parameter(
            "encoding",
            "string",
            "For cat: utf8, or hex for binary content",
            false,
        ),
        parameter(
            "stat",
            "object",
            "For stat: {name, kind, size, mode, owner, mtime}",
            false,
        ),
        parameter(
            "bytes_written",
            "number",
            "For write: bytes the server accepted",
            false,
        ),
    ])
    .with_actions(actions())
});

pub fn check(v: &Value) -> Result<()> {
    let op = v["type"].as_str().unwrap_or_default();
    ensure!(
        matches!(
            op,
            "ninep_ls"
                | "ninep_cat"
                | "ninep_write"
                | "ninep_stat"
                | "ninep_mkdir"
                | "ninep_remove"
                | "ninep_rename"
        ),
        "Unknown 9P client action"
    );
    let path = v["path"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("path must be a string"))?;
    wire::elements(path)?;
    match op {
        "ninep_write" => {
            let data = v["data"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("data must be a string"))?;
            let bytes = wire::from_text(data, v["encoding"].as_str())?;
            ensure!(bytes.len() <= wire::MAX_CONTENT, "data exceeds 1 MiB");
            for key in ["append", "create"] {
                ensure!(
                    v.get(key).is_none_or(Value::is_boolean),
                    "{key} must be a boolean"
                );
            }
        }
        "ninep_rename" => {
            let name = v["name"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("name must be a string"))?;
            wire::check_name(name)?;
            ensure!(name != "..", "invalid name");
        }
        "ninep_mkdir" | "ninep_remove" => {
            ensure!(path != "/", "not the root");
        }
        _ => {}
    }
    Ok(())
}

impl Protocol for NinepClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "9P"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>9P"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["9p", "9p2000", "plan 9", "styx", "ninep"]
    }
    fn description(&self) -> &'static str {
        "9P2000 client: list, read, write, create, remove, rename and stat files on a 9P server"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), RESULT_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "uname".into(),
                type_hint: "string".into(),
                description: "User name sent in Tattach".into(),
                required: false,
                example: json!("glenda"),
                default: Some(json!(super::DEFAULT_UNAME)),
            },
            ParameterDefinition {
                name: "aname".into(),
                type_hint: "string".into(),
                description: "File tree to attach to (aname); empty for the server's default"
                    .into(),
                required: false,
                example: json!(""),
                default: None,
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(564)
            .implementation("9P2000 over Tokio TCP: version, attach without auth, and per action a walk from the root fid, then open/create/read/write/stat/wstat/remove and clunk")
            .llm_control("Which files to list, read, write, create, remove or rename, and what to do with each result")
            .e2e_testing("tests/client/ninep: NetGet's own server for every operation; knusbaum/go9p's file server (Go) as the independent peer")
            .notes("9P2000 only, no authentication. msize is offered at 65536; a file read is capped at 1 MiB, a listing at 1024 entries, a path at 16 elements per walk (longer paths walk in steps). Requests run one at a time; each has a 30 s deadline.")
            .max_inbound_bytes(wire::MAX_MSIZE as usize)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the 9P server at 127.0.0.1:564, list the root and read readme.txt"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"9p","remote_addr":"127.0.0.1:564","instruction":"List the root and read every text file"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"ninep_connected","handler":{"type":"static","actions":[{"type":"ninep_ls","path":"/"}]}},
            {"event_pattern":"ninep_result","handler":{"type":"static","actions":[{"type":"disconnect"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\na=[{'type':'ninep_cat','path':'/'+x['name']} for x in e.get('entries',[]) if x['kind']=='file']\nprint(json.dumps({'actions':a or [{'type':'disconnect'}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
}

impl Client for NinepClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            Some(name) if name.starts_with("ninep_") => {
                check(&v)?;
                Ok(ClientActionResult::Custom {
                    name: name.to_string(),
                    data: v,
                })
            }
            _ => bail!("Unknown 9P client action"),
        }
    }
}

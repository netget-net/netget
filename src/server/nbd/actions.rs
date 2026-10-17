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
pub struct NbdProtocol;
impl NbdProtocol {
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
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(LogTemplate::new().with_info(format!("NBD {name}"))),
    }
}

fn export() -> ActionDefinition {
    action(
        "nbd_export",
        "Serve the requested export read-only: its size and content as extents (text, hex or a fill byte at an offset; everything else reads as zeroes), optional error regions that fail reads, and block sizes. Rust answers every read from this description.",
        vec![
            parameter("size", "number", "Export size in bytes (up to 1 TiB)", true),
            parameter("extents", "array", "[{offset, text} | {offset, hex} | {offset, length, fill: 0-255}], up to 16 MiB of explicit bytes", false),
            parameter("errors", "array", "[{offset, length, error: EIO|EPERM|ENOMEM|EINVAL|ENOSPC}] regions whose reads fail", false),
            parameter("description", "string", "Free-text description shown by NBD_OPT_INFO/GO", false),
            parameter("block_size", "object", "{minimum (default 1), preferred (default 4096), maximum (default 32 MiB)}", false),
        ],
        json!({"type": "nbd_export", "size": 1048576, "description": "boot disk", "extents": [{"offset": 0, "text": "hello"}, {"offset": 4096, "length": 512, "fill": 255}], "errors": [{"offset": 524288, "length": 4096, "error": "EIO"}]}),
    )
}

fn reject() -> ActionDefinition {
    action(
        "nbd_reject",
        "Refuse: the client is told the export is unknown, or that policy forbids it (or the export list)",
        vec![parameter("reason", "string", "unknown (no such export) or policy", true)],
        json!({"type": "nbd_reject", "reason": "unknown"}),
    )
}

fn list() -> ActionDefinition {
    action(
        "nbd_list_exports",
        "Answer NBD_OPT_LIST with the exports this server offers",
        vec![parameter("exports", "array", "[{name, description}]", true)],
        json!({"type": "nbd_list_exports", "exports": [{"name": "disk0", "description": "boot disk"}]}),
    )
}

pub static EXPORT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nbd_export_request",
        "A client asked for an export by name (NBD_OPT_GO, NBD_OPT_INFO or NBD_OPT_EXPORT_NAME); describe it or refuse",
        export().example.clone(),
    )
    .with_parameters(vec![
        parameter("export", "string", "The export name the client asked for (empty for the default export)", true),
        parameter("option", "string", "go, info or export_name", true),
    ])
    .with_actions(vec![export(), reject()])
});

pub static LIST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "nbd_list",
        "A client asked which exports exist (NBD_OPT_LIST)",
        list().example.clone(),
    )
    .with_parameters(vec![parameter(
        "client",
        "string",
        "The client's address",
        true,
    )])
    .with_actions(vec![list(), reject()])
});

impl Protocol for NbdProtocol {
    fn protocol_name(&self) -> &'static str {
        "NBD"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>NBD"
    }
    fn description(&self) -> &'static str {
        "Network Block Device server: read-only exports the handler describes, served by fixed newstyle negotiation with structured replies and block status"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["nbd", "network block device", "block device", "disk image"]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![export(), reject(), list()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![EXPORT_EVENT.clone(), LIST_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(10809)
            .implementation("Native NBD fixed newstyle negotiation (LIST, INFO, GO, EXPORT_NAME, STRUCTURED_REPLY, base:allocation meta context) and transmission (READ, BLOCK_STATUS, FLUSH, CACHE, DISC) over Tokio TCP; exports are read-only and served from the handler's description")
            .llm_control("Which exports exist and what each contains, including regions whose reads fail")
            .e2e_testing("tests/server/nbd: libnbd 1.24.3's nbdinfo and nbdcopy (independent, C) list exports, read export info and allocation maps, copy whole exports and hit error regions")
            .notes("Read-only: writes, trims and zeroing fail with EPERM. One export description per name per connection. No TLS, no extended headers. 64 KiB per option, 32 MiB per request, 16 MiB of explicit content per export, 256 connections.")
            .request_only("NBD answers each request; the server pushes nothing")
            .answers_on_failure()
            .max_inbound_bytes(super::wire::MAX_OPTION)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "NBD server on port 10809 exporting a 1 MiB disk that starts with \"hello\""
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"nbd","port":10809,"instruction":"Export disk0: 1 MiB, starting with hello"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"nbd_export_request","handler":{"type":"static","actions":[{"type":"nbd_export","size":1048576,"extents":[{"offset":0,"text":"hello"}]}]}},
            {"event_pattern":"nbd_list","handler":{"type":"static","actions":[{"type":"nbd_list_exports","exports":[{"name":"disk0"}]}]}}
        ]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"*","handler":{"type":"script","language":"python","code":"import json,sys\ni=json.load(sys.stdin)\nif i['event_type_id']=='nbd_list':\n    a={'type':'nbd_list_exports','exports':[{'name':'disk0'}]}\nelif i['event']['export'] in ('','disk0'):\n    a={'type':'nbd_export','size':1048576,'extents':[{'offset':0,'text':'hello'}]}\nelse:\n    a={'type':'nbd_reject','reason':'unknown'}\nprint(json.dumps({'actions':[a]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Server for NbdProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("nbd_export") => {
                super::wire::Export::from_action(&v)?;
            }
            Some("nbd_reject") => ensure!(
                matches!(v["reason"].as_str(), Some("unknown" | "policy")),
                "reason is unknown or policy"
            ),
            Some("nbd_list_exports") => {
                let exports = v["exports"].as_array().filter(|a| a.len() <= 1024);
                let Some(exports) = exports else {
                    bail!("exports is an array of up to 1024 {{name, description}}")
                };
                for e in exports {
                    ensure!(
                        e["name"].as_str().is_some_and(|n| n.len() <= 4096),
                        "each export has a name up to 4096 bytes"
                    );
                }
            }
            _ => bail!("Unknown NBD server action"),
        }
        Ok(ActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::nbd::actions::{action, parameter};
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct NbdClientProtocol;
impl NbdClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn read() -> ActionDefinition {
    action(
        "nbd_read",
        "Read a range of the export; nbd_read_result reports the bytes (text when UTF-8, else hex; the first 4096 shown), their SHA-256, whether they are all zero, or the server's error",
        vec![
            parameter("offset", "number", "Byte offset into the export", true),
            parameter("length", "number", "Bytes to read (1 to 1048576)", true),
        ],
        json!({"type": "nbd_read", "offset": 0, "length": 512}),
    )
}
fn block_status() -> ActionDefinition {
    action(
        "nbd_block_status",
        "Ask which parts of a range hold data and which are holes reading as zeroes (needs the server's base:allocation context)",
        vec![
            parameter("offset", "number", "Byte offset into the export", true),
            parameter("length", "number", "Bytes to describe (1 to 4294967295)", true),
        ],
        json!({"type": "nbd_block_status", "offset": 0, "length": 1048576}),
    )
}
fn flush() -> ActionDefinition {
    action(
        "nbd_flush",
        "Send NBD_CMD_FLUSH and report the server's answer",
        vec![],
        json!({"type": "nbd_flush"}),
    )
}
fn disconnect() -> ActionDefinition {
    action(
        "disconnect",
        "Send NBD_CMD_DISC and close the connection",
        vec![],
        json!({"type": "disconnect"}),
    )
}

pub fn all_actions() -> Vec<ActionDefinition> {
    vec![read(), block_status(), flush(), disconnect()]
}

fn event(id: &str, description: &str, params: Vec<crate::llm::actions::Parameter>) -> EventType {
    EventType::new(id, description, read().example.clone())
        .with_parameters(params)
        .with_actions(all_actions())
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "nbd_connected",
        "Negotiation finished and the export is open",
        vec![
            parameter("export", "string", "The export name", true),
            parameter("size", "number", "Export size in bytes", true),
            parameter(
                "read_only",
                "boolean",
                "Whether the server marked the export read-only",
                true,
            ),
            parameter(
                "description",
                "string",
                "The server's description of the export",
                false,
            ),
            parameter(
                "block_size",
                "object",
                "{minimum, preferred, maximum} when the server sent them",
                false,
            ),
            parameter(
                "structured_replies",
                "boolean",
                "Whether structured replies were negotiated",
                true,
            ),
            parameter(
                "base_allocation",
                "boolean",
                "Whether block status is available",
                true,
            ),
            parameter(
                "exports",
                "array",
                "The server's export list, when list_exports was set",
                false,
            ),
        ],
    )
});
pub static READ_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "nbd_read_result",
        "The server answered a read",
        vec![
            parameter("offset", "number", "Where the read started", true),
            parameter("length", "number", "How many bytes were asked for", true),
            parameter(
                "error",
                "string",
                "The server's error (EIO, EINVAL, ...) when the read failed",
                false,
            ),
            parameter(
                "error_offset",
                "number",
                "The first failing byte, when the server named it",
                false,
            ),
            parameter(
                "data",
                "string",
                "The first 4096 bytes: text when UTF-8, else hex per data_encoding",
                false,
            ),
            parameter(
                "data_encoding",
                "string",
                "utf8 when data is text, hex when it is not UTF-8",
                false,
            ),
            parameter("sha256", "string", "SHA-256 of all the bytes read", false),
            parameter(
                "all_zero",
                "boolean",
                "Whether every byte read was zero",
                false,
            ),
        ],
    )
});
pub static STATUS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "nbd_block_status_result",
        "The server described a range's allocation, or refused",
        vec![
            parameter("offset", "number", "Where the range started", true),
            parameter("extents", "array", "[{offset, length, hole, zero}]", false),
            parameter(
                "error",
                "string",
                "The server's error when it refused",
                false,
            ),
        ],
    )
});
pub static FLUSH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "nbd_flush_result",
        "The server answered a flush",
        vec![parameter(
            "error",
            "string",
            "OK, or the server's error",
            true,
        )],
    )
});

impl Protocol for NbdClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "NBD"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>NBD"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["nbd", "nbd client", "network block device"]
    }
    fn description(&self) -> &'static str {
        "Network Block Device client: negotiates an export and reads it, with block status"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        all_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            READ_EVENT.clone(),
            STATUS_EVENT.clone(),
            FLUSH_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "export".into(),
                type_hint: "string".into(),
                description: "Export name to open (empty for the server's default)".into(),
                required: false,
                example: json!("disk0"),
                default: Some(json!(super::DEFAULT_EXPORT)),
            },
            ParameterDefinition {
                name: "list_exports".into(),
                type_hint: "boolean".into(),
                description: "Ask for the export list (NBD_OPT_LIST) before opening".into(),
                required: false,
                example: json!(true),
                default: Some(json!(super::DEFAULT_LIST_EXPORTS)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("The server's NBD wire constants; fixed newstyle negotiation (LIST, STRUCTURED_REPLY, SET_META_CONTEXT base:allocation, GO) and one request at a time")
            .llm_control("Which ranges to read and describe, and when to disconnect")
            .e2e_testing("tests/client/nbd: nbdkit 1.48.1 (independent, C) serving its data plugin, with its error filter injecting EIO")
            .notes("Read-only client: no write, trim or zero commands. No TLS or extended headers. Reads up to 1 MiB.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Open export disk0 on the NBD server at 127.0.0.1:10809 and read its first sector"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"nbd","remote_addr":"127.0.0.1:10809","instruction":"Read the first 512 bytes of disk0","startup_params":{"export":"disk0"}});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"nbd_connected","handler":{"type":"static","actions":[read().example]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"nbd_connected","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'nbd_read','offset':0,'length':min(512,e['size'])}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Client for NbdClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("disconnect") => return Ok(ClientActionResult::Disconnect),
            Some("nbd_read") => ensure!(
                v["offset"].as_u64().is_some()
                    && matches!(v["length"].as_u64(), Some(1..=1_048_576)),
                "offset is a byte offset and length 1 to 1048576"
            ),
            Some("nbd_block_status") => ensure!(
                v["offset"].as_u64().is_some()
                    && matches!(v["length"].as_u64(), Some(1..=4_294_967_295)),
                "offset is a byte offset and length 1 to 4294967295"
            ),
            Some("nbd_flush") => {}
            _ => bail!("Unknown NBD client action"),
        }
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().into(),
            data: v,
        })
    }
}

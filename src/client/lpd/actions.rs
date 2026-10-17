use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::lpd::{
    actions::{action, parameter},
    wire,
};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct LpdClientProtocol;
impl LpdClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

pub const DEFAULT_HOST: &str = "netget";
pub const DEFAULT_USER: &str = "netget";
/// Largest document the client will send in one job.
pub const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;

fn print_action() -> ActionDefinition {
    action(
        "lpd_print",
        "Submit a text document as one print job on its own connection; the result arrives as lpd_print_result.",
        vec![
            parameter("queue", "string", "Queue name on the LPD server, such as raw", true),
            parameter("text", "string", "Document text, sent as the job's data file", true),
            parameter("job_name", "string", "Job name shown by lpq (J line)", false),
            parameter("format", "string", "Print format letter: f (plain text, default), l (literal), o (PostScript)", false),
            parameter(
                "order",
                "string",
                "Which file to send first: control_first (default, as LPRng does) or data_first (as BSD lpr does)",
                false,
            ),
        ],
        json!({"type":"lpd_print","queue":"raw","text":"Hello printer","job_name":"hello"}),
    )
}

fn queue_action() -> ActionDefinition {
    action(
        "lpd_queue",
        "Ask for a queue listing (lpq); the server's text arrives as lpd_reply.",
        vec![
            parameter(
                "queue",
                "string",
                "Name of the print queue on the server",
                true,
            ),
            parameter("long", "boolean", "True for the long format", false),
            parameter(
                "list",
                "array",
                "Users or job numbers to restrict the listing to",
                false,
            ),
        ],
        json!({"type":"lpd_queue","queue":"raw"}),
    )
}

fn remove_action() -> ActionDefinition {
    action(
        "lpd_remove",
        "Ask the server to remove jobs (lprm); the server's text arrives as lpd_reply.",
        vec![
            parameter(
                "queue",
                "string",
                "Name of the print queue on the server",
                true,
            ),
            parameter(
                "agent",
                "string",
                "User on whose behalf the jobs are removed",
                true,
            ),
            parameter(
                "jobs",
                "array",
                "Job numbers or user names to remove; empty means the agent's active job",
                false,
            ),
        ],
        json!({"type":"lpd_remove","queue":"raw","agent":"alice","jobs":["42"]}),
    )
}

fn start_action() -> ActionDefinition {
    action(
        "lpd_start_queue",
        "Ask the server to print any waiting jobs on a queue. LPD defines no reply.",
        vec![parameter(
            "queue",
            "string",
            "Name of the print queue on the server",
            true,
        )],
        json!({"type":"lpd_start_queue","queue":"raw"}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Stop this LPD client",
        vec![],
        json!({"type":"disconnect"}),
    )
}

fn actions() -> Vec<ActionDefinition> {
    vec![
        print_action(),
        queue_action(),
        remove_action(),
        start_action(),
        disconnect_action(),
    ]
}

pub static READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "lpd_ready",
        "The LPD server is reachable. LPD carries one command per connection, so each action dials anew.",
        print_action().example.clone(),
    )
    .with_parameters(vec![parameter("remote_addr", "string", "LPD server address", true)])
    .with_actions(actions())
});

pub static PRINT_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "lpd_print_result",
        "Outcome of one lpd_print: accepted is true only when the server acknowledged every step with 0",
        disconnect_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("queue", "string", "Queue the job was sent to", true),
        parameter("job_id", "string", "Three-digit job number", true),
        parameter("accepted", "boolean", "True when the server queued the job", true),
        parameter("refused_at", "string", "queue, control, data or final when the server refused; null when accepted", false),
    ])
    .with_actions(actions())
});

pub static REPLY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "lpd_reply",
        "Text the server sent for a queue listing, removal or print-waiting request",
        disconnect_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("command", "string", "queue, remove or start_queue", true),
        parameter(
            "queue",
            "string",
            "Name of the print queue on the server",
            true,
        ),
        parameter(
            "text",
            "string",
            "The server's reply text (empty for start_queue)",
            true,
        ),
    ])
    .with_actions(actions())
});

/// A validated client command.
#[derive(Debug, Clone)]
pub enum Command {
    Print {
        queue: String,
        text: String,
        job_name: Option<String>,
        format: char,
        data_first: bool,
    },
    Queue {
        queue: String,
        long: bool,
        list: Vec<String>,
    },
    Remove {
        queue: String,
        agent: String,
        jobs: Vec<String>,
    },
    Start {
        queue: String,
    },
}

fn token(v: &Value, key: &str) -> Result<String> {
    v[key]
        .as_str()
        .filter(|s| wire::valid_token(s))
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("{key} must be a name without spaces"))
}

fn tokens(v: &Value, key: &str) -> Result<Vec<String>> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => {
            ensure!(items.len() <= 64, "{key} lists at most 64 entries");
            items
                .iter()
                .map(|item| match item {
                    Value::String(s) if wire::valid_token(s) => Ok(s.clone()),
                    Value::Number(n) => Ok(n.to_string()),
                    _ => bail!("{key} entries must be names or numbers without spaces"),
                })
                .collect()
        }
        _ => bail!("{key} must be an array"),
    }
}

impl Command {
    pub fn from_action(v: &Value) -> Result<Self> {
        match v["type"].as_str() {
            Some("lpd_print") => {
                let text = v["text"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("text must be a string"))?;
                ensure!(
                    text.len() <= MAX_DOCUMENT_BYTES,
                    "text exceeds {MAX_DOCUMENT_BYTES} bytes"
                );
                let job_name = match v.get("job_name") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s))
                        if s.len() <= 99 && !crate::utils::sanitize::has_controls(s) =>
                    {
                        Some(s.clone())
                    }
                    _ => bail!("job_name must be a single line of at most 99 characters"),
                };
                let format = match v.get("format").and_then(Value::as_str) {
                    None => 'f',
                    Some(f) if f.len() == 1 && "cdfglnoprtvz".contains(f) => {
                        f.chars().next().unwrap_or('f')
                    }
                    Some(_) => {
                        bail!("format must be one RFC 1179 format letter, such as f, l or o")
                    }
                };
                let data_first = match v.get("order").and_then(Value::as_str) {
                    None | Some("control_first") => false,
                    Some("data_first") => true,
                    Some(_) => bail!("order must be control_first or data_first"),
                };
                Ok(Command::Print {
                    queue: token(v, "queue")?,
                    text: text.to_string(),
                    job_name,
                    format,
                    data_first,
                })
            }
            Some("lpd_queue") => Ok(Command::Queue {
                queue: token(v, "queue")?,
                long: v.get("long").and_then(Value::as_bool).unwrap_or(false),
                list: tokens(v, "list")?,
            }),
            Some("lpd_remove") => Ok(Command::Remove {
                queue: token(v, "queue")?,
                agent: token(v, "agent")?,
                jobs: tokens(v, "jobs")?,
            }),
            Some("lpd_start_queue") => Ok(Command::Start {
                queue: token(v, "queue")?,
            }),
            _ => bail!("Unknown LPD client action"),
        }
    }
}

impl Protocol for LpdClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "LPD"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>LPD"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["lpd", "lpr", "lpq", "lprm", "rfc1179", "line printer"]
    }
    fn description(&self) -> &'static str {
        "LPD client that submits print jobs, lists queues and removes jobs"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            READY_EVENT.clone(),
            PRINT_RESULT_EVENT.clone(),
            REPLY_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "host".into(),
                type_hint: "string".into(),
                description: "Host name written into control files (H line) and job file names"
                    .into(),
                required: false,
                example: json!("workstation"),
                default: Some(json!(DEFAULT_HOST)),
            },
            ParameterDefinition {
                name: "user".into(),
                type_hint: "string".into(),
                description: "User name written into control files (P line)".into(),
                required: false,
                example: json!("alice"),
                default: Some(json!(DEFAULT_USER)),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(515)
            .implementation("Tokio TCP, one connection per command: receive job with control and data files in either order, short and long queue listings, removal, print-waiting")
            .llm_control("Which documents to print on which queue, listings to ask for, jobs to remove, and what to do with each reply")
            .e2e_testing("tests/client/lpd: scripted fixture asserting control files and acknowledgements; LPRng lpd as the independent server")
            .notes("Connects from an unprivileged source port, so a server enforcing RFC 1179's 721-731 source ports will refuse it. Text documents only (up to 4 MiB). Replies are bounded to 1 MiB; connect, write and acknowledgement deadlines are 30 s.")
            .max_inbound_bytes(wire::MAX_REPLY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to LPD at 127.0.0.1:5515 and print a test page on queue raw"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"lpd","remote_addr":"127.0.0.1:5515","instruction":"Print a test page on queue raw"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"lpd_ready","handler":{"type":"static","actions":[{"type":"lpd_print","queue":"raw","text":"Test page","job_name":"test"}]}},
            {"event_pattern":"lpd_print_result","handler":{"type":"static","actions":[{"type":"lpd_queue","queue":"raw"}]}},
            {"event_pattern":"lpd_reply","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'lpd_print','queue':'raw','text':'Test page'}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Client for LpdClientProtocol {
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
            Some(name) => {
                Command::from_action(&v)?;
                Ok(ClientActionResult::Custom {
                    name: name.to_string(),
                    data: v,
                })
            }
            None => bail!("Unknown LPD client action"),
        }
    }
}

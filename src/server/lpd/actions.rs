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
pub struct LpdProtocol;
impl LpdProtocol {
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
        "lpd_job_reply" => LogTemplate::new().with_info("-> LPD job accept={accept}"),
        "lpd_queue_status" => {
            LogTemplate::new().with_info("-> LPD queue status={status} jobs={preview(jobs,120)}")
        }
        "lpd_remove_result" => {
            LogTemplate::new().with_info("-> LPD removed={preview(removed,120)}")
        }
        "lpd_print" => {
            LogTemplate::new().with_info("-> LPD print queue={queue} job_name={job_name}")
        }
        "lpd_queue" => LogTemplate::new().with_info("-> LPD queue query queue={queue} long={long}"),
        "lpd_remove" => LogTemplate::new().with_info("-> LPD remove queue={queue} agent={agent}"),
        "lpd_start_queue" => {
            LogTemplate::new().with_info("-> LPD print waiting jobs queue={queue}")
        }
        _ => LogTemplate::new().with_info(format!("-> LPD {name}")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}

fn job_action() -> ActionDefinition {
    action(
        "lpd_job_reply",
        "Accept or refuse the print job. Acceptance acknowledges the job's last file with 0; refusal sends a nonzero acknowledgement, which tells the client the job was not queued.",
        vec![
            parameter("accept", "boolean", "True to queue the job", true),
            parameter("reason", "string", "Why, for the log; LPD has no field to carry it to the client", false),
        ],
        json!({"type":"lpd_job_reply","accept":true}),
    )
}

fn queue_action() -> ActionDefinition {
    action(
        "lpd_queue_status",
        "Describe the queue for lpq. Rust renders the short or long listing the client asked for.",
        vec![
            parameter("status", "string", "First line, such as 'raw is ready and printing'", false),
            parameter(
                "jobs",
                "array",
                "Queued jobs in order: [{owner, job_id: number, files: string, size: bytes, rank?: 'active' or a number}]",
                false,
            ),
        ],
        json!({"type":"lpd_queue_status","status":"raw is ready","jobs":[{"owner":"alice","job_id":42,"files":"report.txt","size":1024}]}),
    )
}

fn remove_action() -> ActionDefinition {
    action(
        "lpd_remove_result",
        "Report which jobs the removal request dequeued; each is listed back to lprm as dequeued.",
        vec![parameter(
            "removed",
            "array",
            "Job numbers removed, such as [42]; empty when nothing matched",
            true,
        )],
        json!({"type":"lpd_remove_result","removed":[42]}),
    )
}

pub static JOB_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "lpd_print_job",
        "A complete print job: the control file and every data file it names have arrived. Decide whether to queue it.",
        job_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("queue", "string", "Queue the client sent the job to", true),
        parameter("job_id", "string", "Three-digit job number from the control file name", true),
        parameter("host", "string", "Originating host (H line)", false),
        parameter("user", "string", "Submitting user (P line)", false),
        parameter("job_name", "string", "Job name (J line)", false),
        parameter("title", "string", "Title for pr formatting (T line)", false),
        parameter("class", "string", "Job class from the control file (C line)", false),
        parameter("mail", "string", "Address to mail on completion (M line)", false),
        parameter(
            "files",
            "array",
            "[{name, source_name, format, size, text}] - text is the first 64 KiB when the file is text, null when binary",
            true,
        ),
    ])
    .with_actions(vec![job_action()])
});

pub static QUEUE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "lpd_queue_query",
        "A client (lpq) asked for the state of a queue.",
        queue_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "queue",
            "string",
            "Name of the print queue on the server",
            true,
        ),
        parameter("long", "boolean", "True for the long format (lpq -l)", true),
        parameter(
            "list",
            "array",
            "Users or job numbers the listing is restricted to",
            true,
        ),
    ])
    .with_actions(vec![queue_action()])
});

pub static REMOVE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "lpd_remove_request",
        "A client (lprm) asked to remove jobs. The agent is the user asking.",
        remove_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "queue",
            "string",
            "Name of the print queue on the server",
            true,
        ),
        parameter("agent", "string", "User requesting removal", true),
        parameter(
            "list",
            "array",
            "Users or job numbers to remove; empty means the agent's current job",
            true,
        ),
    ])
    .with_actions(vec![remove_action()])
});

impl Protocol for LpdProtocol {
    fn protocol_name(&self) -> &'static str {
        "LPD"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>LPD"
    }
    fn description(&self) -> &'static str {
        "LPD line printer daemon (RFC 1179): print jobs, queue listings and removals"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "lpd",
            "lpr",
            "lpq",
            "lprm",
            "rfc1179",
            "line printer",
            "print server",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![job_action(), queue_action(), remove_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![JOB_EVENT.clone(), QUEUE_EVENT.clone(), REMOVE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "queues".into(),
                type_hint: "array".into(),
                description: "Queue names to accept; a job for any other queue is refused at once. Omit to accept every queue.".into(),
                required: false,
                example: json!(["raw", "laser"]),
                default: None,
            },
            ParameterDefinition {
                name: "max_job_bytes".into(),
                type_hint: "number".into(),
                description: "Total size of the data files in one job (1..=268435456)".into(),
                required: false,
                example: json!(1048576),
                default: Some(json!(super::wire::DEFAULT_MAX_JOB_BYTES)),
            },
            ParameterDefinition {
                name: "idle_timeout_secs".into(),
                type_hint: "number".into(),
                description: "Seconds to wait for each command line or file transfer (1..=3600)".into(),
                required: false,
                example: json!(60),
                default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::PrivilegedPort(515))
            .well_known_port(515)
            .implementation("RFC 1179 over Tokio TCP: receive job (control and data files in either order, abort), short and long queue state, remove jobs, print waiting jobs")
            .llm_control("Whether each complete print job is queued, what the queue listing says, and which jobs a removal dequeues")
            .e2e_testing("tests/server/lpd: raw-wire jobs and bounds; LPRng lpr/lpq/lprm and the CUPS lpd backend as independent clients")
            .notes("No spool: the handler sees every job's control fields and the text of each data file (first 64 KiB, null when binary) and decides; nothing is printed or kept. Source ports are not checked against the RFC's 721-731 range. A data file must declare its exact size (no count-0 streaming). Bounds: 1024-byte command lines, 64 KiB control files, 52 data files and max_job_bytes per job, per-read idle deadline. A handler failure refuses the job (nonzero acknowledgement), answers a queue query with an unavailable line, and removes nothing.")
            .request_only("LPD answers the one command each connection carries; the server never speaks first")
            .max_inbound_bytes(super::wire::MAX_COMMAND_LINE)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "LPD print server on port 5515 with a queue named raw that accepts plain-text jobs"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"lpd","port":5515,"instruction":"Accept text jobs on queue raw","startup_params":{"queues":["raw"]}});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([
            {"event_pattern":"lpd_print_job","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nok=all(f['text'] is not None for f in e['files'])\nprint(json.dumps({'actions':[{'type':'lpd_job_reply','accept':ok}]}))"}},
            {"event_pattern":"lpd_queue_query","handler":{"type":"static","actions":[{"type":"lpd_queue_status","status":"raw is ready","jobs":[]}]}},
            {"event_pattern":"lpd_remove_request","handler":{"type":"static","actions":[{"type":"lpd_remove_result","removed":[]}]}}
        ]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"lpd_print_job","handler":{"type":"static","actions":[{"type":"lpd_job_reply","accept":true}]}},
            {"event_pattern":"lpd_queue_query","handler":{"type":"static","actions":[{"type":"lpd_queue_status","status":"raw is ready","jobs":[]}]}},
            {"event_pattern":"lpd_remove_request","handler":{"type":"static","actions":[{"type":"lpd_remove_result","removed":[]}]}}
        ]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Server for LpdProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("lpd_job_reply") => {
                ensure!(v["accept"].is_boolean(), "accept must be a boolean");
                Ok(ActionResult::Custom {
                    name: "lpd_job_reply".into(),
                    data: v,
                })
            }
            Some("lpd_queue_status") => {
                ensure!(
                    v.get("status").is_none_or(Value::is_string),
                    "status must be a string"
                );
                if let Some(jobs) = v.get("jobs") {
                    let jobs = jobs
                        .as_array()
                        .ok_or_else(|| anyhow::anyhow!("jobs must be an array"))?;
                    ensure!(jobs.len() <= 1000, "at most 1000 jobs in one listing");
                    for job in jobs {
                        ensure!(job.is_object(), "each job must be an object");
                    }
                }
                Ok(ActionResult::Custom {
                    name: "lpd_queue_status".into(),
                    data: v,
                })
            }
            Some("lpd_remove_result") => {
                let removed = v["removed"]
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("removed must be an array"))?;
                ensure!(removed.len() <= 1000, "at most 1000 removed jobs");
                for id in removed {
                    ensure!(
                        id.is_u64() || id.as_str().is_some_and(super::wire::valid_token),
                        "each removed job must be a number"
                    );
                }
                Ok(ActionResult::Custom {
                    name: "lpd_remove_result".into(),
                    data: v,
                })
            }
            _ => bail!("Unknown LPD server action"),
        }
    }
}

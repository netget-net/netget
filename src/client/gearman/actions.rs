use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct GearmanClientProtocol;
impl GearmanClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
fn p(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}
fn submitter() -> ActionDefinition {
    ActionDefinition{name:"gearman_request".into(),description:"Submit a Gearman job, query its status, echo text, or enable exceptions. Requests and job updates are correlated separately.".into(),parameters:vec![
        p("operation","string","submit/status/echo/enable_exceptions",true),
        p("function_name","string","Job function, 1..512 UTF-8 bytes without NUL",false),
        p("unique_id","string","Optional unique job key, at most 64 UTF-8 bytes without NUL",false),
        p("workload","string","UTF-8 workload; wire byte count is computed by Rust",false),
        p("priority","string","normal/high/low; default normal",false),
        p("background","boolean","Submit without receiving worker updates; default false",false),
        p("job_handle","string","Handle from job_created for status",false),
        p("data","string","UTF-8 text returned by the daemon for an echo request",false),
    ],example:json!({"type":"gearman_request","operation":"submit","function_name":"reverse","workload":"hello"}),log_template: Some(LogTemplate::new().with_info("Gearman submitter operation {operation}"))}
}
fn worker() -> ActionDefinition {
    ActionDefinition{name:"gearman_worker".into(),description:"Selected worker role: advertise abilities, grab jobs, sleep until noop, and answer only handles assigned to this connection. No automatic completion.".into(),parameters:vec![
        p("operation","string","register/unregister/reset/grab/grab_unique/sleep/set_id/progress/data/warning/complete/fail/exception",true),
        p("function_name","string","Ability name for register/unregister",false),
        p("client_id","string","Worker identifier for set_id, 1..64 bytes without NUL",false),
        p("job_handle","string","Assigned handle for work replies",false),
        p("numerator","integer","Progress numerator, 0..denominator",false),
        p("denominator","integer","Positive progress denominator, at most u32::MAX",false),
        p("data","string","UTF-8 intermediate data or warning",false),
        p("result","string","UTF-8 completion result",false),
        p("text","string","UTF-8 exception text; terminal outcome",false),
    ],example:json!({"type":"gearman_worker","operation":"register","function_name":"reverse"}),log_template: Some(LogTemplate::new().with_info("Gearman worker operation {operation}"))}
}
fn disconnect() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".into(),
        description: "Close Gearman immediately, including a stalled request or parked handler"
            .into(),
        parameters: vec![],
        example: json!({"type":"disconnect"}),
        log_template: Some(
            LogTemplate::new().with_info("Disconnect Gearman daemon and cancel pending work"),
        ),
    }
}
fn actions() -> Vec<ActionDefinition> {
    vec![submitter(), worker(), disconnect()]
}
fn event(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, submitter().example)
        .with_parameters(params)
        .with_actions(actions())
}
pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "gearman_connected",
        "Connected; submit a job or register worker abilities according to role.",
        vec![
            p(
                "remote_addr",
                "string",
                "Gearman daemon TCP socket address",
                true,
            ),
            p("role", "string", "submitter or worker", true),
        ],
    )
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("gearman_response","Validated response to a request: job_created, status, echo, option, no_job or job_assigned.",vec![p("request","object","Typed originating request",true),p("response","object","Typed response including handles, payload text/bytes/utf8 and status fields",true)])
});
pub static UPDATE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("gearman_job_update","Progress/data/warning or terminal complete/fail/exception, correlated with its submitted foreground job.",vec![p("request","object","Original submit action",true),p("job_handle","string","Correlated handle",true),p("kind","string","progress/data/warning/complete/fail/exception",true),p("terminal","boolean","Whether job is finished",true),p("payload","object","Text (null for binary), exact bytes and UTF-8 flag where present",false),p("numerator","integer","Progress numerator",false),p("denominator","integer","Progress denominator",false)])
});
pub static WAKE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "gearman_worker_wakeup",
        "NOOP wakes a sleeping worker; explicitly grab again.",
        vec![],
    )
});
pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("gearman_error","Server ERROR refusal. The connection closes because no request IDs safely correlate asynchronous worker errors.",vec![p("code","string","Protocol error code",true),p("description","string","Daemon explanation of the rejected request",true),p("request","object","Pending request if present; otherwise null",false)])
});
impl Protocol for GearmanClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Gearman"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Gearman"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["gearman", "gearmand", "jobs", "worker"]
    }
    fn description(&self) -> &'static str {
        "Gearman submitter and bounded selected worker exchanges"
    }
    fn group_name(&self) -> &'static str {
        "Messaging"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to Gearman at localhost:4730 and submit a reverse job"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            RESPONSE_EVENT.clone(),
            UPDATE_EVENT.clone(),
            WAKE_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![crate::llm::actions::ParameterDefinition {
            name: "role".into(),
            type_hint: "string".into(),
            description: "submitter (default) or worker; worker actions require worker role".into(),
            required: false,
            example: json!("worker"),
            default: Some(json!(super::wire::DEFAULT_ROLE)),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).well_known_port(4730)
        .implementation("Tokio TCP; shared binary codec, continuous bounded response reader, correlated foreground jobs and selected worker assignments")
        .llm_control("Priority/background job submission, status/echo/exceptions; selected worker ability registration, grab/grab_unique, sleep/noop and typed work outcomes")
        .e2e_testing("tests/client/gearman: independent gearmand plus gearman CLI producer/worker, NetGet submitter/server pair, framing/correlation/bounds/cancellation and mocked model")
        .notes("Plain TCP, UTF-8 outbound payloads; binary inbound payloads expose null text and exact byte count. No TLS/auth, admin, scheduled/reduce jobs, timed abilities, reconnect or persistent job storage. At most64 foreground jobs/assigned handles and64 abilities; frame body1MiB, partial-frame/write/request deadline15s, bounded queues16, followups4. Idle sleeping workers and jobs may wait; disconnect/removal cancels every owned task. NetGet server remains model-as-worker and refuses worker clients.")
        .max_inbound_bytes(crate::server::gearman::wire::MAX_PACKET_BYTES).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","base_stack":"gearman","protocol":"gearman","remote_addr":"127.0.0.1:4730","instruction":"Submit reverse hello"});
        let mut fixed = llm.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"gearman_connected","handler":{"type":"static","actions":[submitter().example]}},{"event_pattern":"*","handler":{"type":"static","actions":[]}}]);
        let mut script = fixed.clone();
        script["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json, sys\njson.dump({'actions':[{'type':'gearman_request','operation':'submit','function_name':'reverse','workload':'hello'}]}, sys.stdout)"});
        crate::llm::actions::StartupExamples::new(llm, script, fixed)
    }
}
impl Client for GearmanClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("gearman_request" | "gearman_worker") => {
                super::wire::request(&v)?;
                Ok(ClientActionResult::Custom {
                    name: "gearman_request".into(),
                    data: v,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown Gearman client action"),
        }
    }
}

use super::wire::Request;
use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::state::app_state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct BeanstalkdClientProtocol;
impl BeanstalkdClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
fn parameter(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}
fn action(
    name: &str,
    description: &str,
    parameters: Vec<Parameter>,
    example: Value,
    log_template: LogTemplate,
) -> ActionDefinition {
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}
fn request_action() -> ActionDefinition {
    action("beanstalkd_request", "Send a typed work-queue operation; requests are serialized and complete responses become beanstalkd_response events.", vec![
        parameter("operation","string","put/use/watch/ignore/reserve/reserve_job/delete/release/bury/touch/peek/peek_ready/peek_delayed/peek_buried/kick/kick_job/stats/stats_job/stats_tube/list_tubes/list_tube_used/list_tubes_watched/pause_tube/quit",true),
        parameter("tube","string","Tube name for use/watch/ignore/stats_tube/pause_tube",false),
        parameter("id","integer","Positive job ID for job operations",false),
        parameter("body","string","UTF-8 job text for put; byte length is computed by Rust (maximum 65535 bytes)",false),
        parameter("priority","integer","u32 priority; default 1024",false),
        parameter("delay","integer","u32 delay seconds; default 0",false),
        parameter("ttr","integer","put time to run in seconds, u32; default 60",false),
        parameter("timeout_secs","integer","reserve wait 0..=25 seconds; default 0. Encoded as reserve-with-timeout.",false),
        parameter("count","integer","Maximum jobs to kick; default 1",false),
    ],json!({"type":"beanstalkd_request","operation":"stats"}), LogTemplate::new().with_info("-> Beanstalkd {operation}"))
}
fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the Beanstalkd connection",
        vec![],
        json!({"type":"disconnect"}),
        LogTemplate::new().with_info("-> Beanstalkd disconnect"),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![request_action(), disconnect_action()]
}
pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "beanstalkd_connected",
        "Connected to Beanstalkd; send a request",
        request_action().example.clone(),
    )
    .with_parameters(vec![parameter(
        "remote_addr",
        "string",
        "Beanstalkd server address",
        true,
    )])
    .with_actions(actions())
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "beanstalkd_response",
        "Complete, validated work-queue response including protocol refusals.",
        disconnect_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("request", "object", "Structured request", true),
        parameter(
            "response",
            "object",
            "status plus job id/body, count, tube or structured YAML data",
            true,
        ),
    ])
    .with_actions(actions())
});
impl Protocol for BeanstalkdClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Beanstalkd"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Beanstalkd"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["beanstalkd", "work queue", "jobs", "tubes"]
    }
    fn description(&self) -> &'static str {
        "Beanstalkd work-queue client with structured jobs, tubes and statistics"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), RESPONSE_EVENT.clone()]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).well_known_port(11300)
        .implementation("Tokio TCP with strict CRLF and byte-counted UTF-8 jobs; bounded complete response parsing")
        .llm_control("Job put/reserve/release/bury/kick/delete, tube selection/watch/pause, and structured statistics")
        .e2e_testing("tests/client/beanstalkd: installed independent beanstalkd daemon, NetGet server pair, wire bounds, command injection and cleanup")
        .notes("Plain TCP; no authentication (the wire protocol defines none). UTF-8 job payloads only. Connect/response/write deadlines 30s; reservation wait at most25s, response headers224 bytes, jobs65535 bytes and total payload1MiB. All tasks tracked; injected disconnect interrupts pending replies.")
        .max_inbound_bytes(super::wire::MAX_REPLY_BYTES).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to Beanstalkd at localhost:11300 and inspect queue statistics"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"beanstalkd","remote_addr":"127.0.0.1:11300","instruction":"Inspect work-queue statistics"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"beanstalkd_connected","handler":{"type":"static","actions":[{"type":"beanstalkd_request","operation":"stats"}]}},{"event_pattern":"beanstalkd_response","handler":{"type":"static","actions":[]}}]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"respond([{'type':'beanstalkd_request','operation':'stats'}])"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Messaging"
    }
}
impl Client for BeanstalkdClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("beanstalkd_request") => {
                Request::from_action(&v)?;
                Ok(ClientActionResult::Custom {
                    name: "beanstalkd_request".into(),
                    data: v,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown Beanstalkd client action"),
        }
    }
}

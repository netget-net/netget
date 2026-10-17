use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::{log_template::LogTemplate, ConnectContext, EventType};
use crate::state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct DockerClientProtocol;
impl DockerClientProtocol {
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
fn request() -> ActionDefinition {
    ActionDefinition{name:"docker_request".into(),description:"Read one selected Docker Engine API resource using the negotiated API version. No arbitrary URLs, HTTP methods, request bodies or mutations.".into(),parameters:vec![
    p("operation","string","ping, version, info, containers, container, images, networks, or volumes",true),
    p("container_id","string","Required ID or name for container inspect; no slashes",false),
    p("all","boolean","containers/images: include stopped containers or intermediate images; daemon default false",false),
    p("limit","integer","containers: most recent 1..1000 including stopped",false),
    p("size","boolean","containers/container: request filesystem sizes",false),
    p("digests","boolean","images: include repository digests",false),
    p("filters","object","containers/images/networks/volumes: Docker filter name to string arrays, JSON encoded by client",false)
],example:json!({"type":"docker_request","operation":"containers","all":true,"filters":{"label":["netget.fixture=1"]}}),log_template:Some(LogTemplate::new().with_info("Read Docker {operation}"))}
}
fn disconnect() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".into(),
        description: "Cancel pending I/O and close this logical client".into(),
        parameters: vec![],
        example: json!({"type":"disconnect"}),
        log_template: Some(LogTemplate::new().with_info("Disconnect Docker client")),
    }
}
fn actions() -> Vec<ActionDefinition> {
    vec![request(), disconnect()]
}
fn event(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, request().example)
        .with_parameters(params)
        .with_actions(actions())
}
pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("docker_connected","Daemon HEAD /_ping completed; request a read operation",vec![p("endpoint","string","HTTP origin or native Unix socket URI",true),p("api_version","string","Selected min(daemon maximum, preferred client ceiling)",true),p("daemon","object","Ping API maximum, optional os_type and experimental headers; ping does not advertise minimum API",true)])
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("docker_response","Complete typed response; unknown extension fields are omitted",vec![p("request","object","Originating typed action",true),p("operation","string","Selected Docker Engine read operation",true),p("api_version","string","Negotiated request version",true),p("status","integer","Successful Docker Engine HTTP response status (200)",true),p("data","object|array","Snake case selected native response fields. Lists for containers/images/networks; container inspect has state/config/host_config/network_settings objects; volumes object has nullable volumes/warnings. Container/image created timestamps are Unix seconds; inspect/network/volume dates remain RFC3339 strings. Native nulls remain null; image shared_size/containers and volume usage may use -1 for unknown. Ports use protocol and optional public_port/ip. No protocol database.",true)])
});
pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "docker_request_error",
        "Request failed; no partial response is accepted, client remains available",
        vec![
            p("request", "object", "Originating action", true),
            p("api_version", "string", "Negotiated version", true),
            p(
                "status",
                "integer|null",
                "HTTP status when response received",
                true,
            ),
            p("category", "string", "http, schema, or transport", true),
            p(
                "error",
                "string",
                "Docker JSON message or validation/transport/deadline failure",
                true,
            ),
        ],
    )
});
impl Protocol for DockerClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Docker"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Docker"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["docker", "engine", "containers"]
    }
    fn description(&self) -> &'static str {
        "Read typed Docker Engine API resources"
    }
    fn group_name(&self) -> &'static str {
        "AI & API"
    }
    fn example_prompt(&self) -> &'static str {
        "List containers from Docker at localhost:2375"
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
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
        ParameterDefinition{name:"api_version".into(),type_hint:"string".into(),description:"Preferred API ceiling1.24..1.47; negotiate down using daemon HEAD /_ping API-Version. A newer daemon minimum can still refuse the selected version with a typed HTTP error.".into(),required:false,example:json!("1.47"),default:Some(json!(super::DEFAULT_API_VERSION))},
        ParameterDefinition{name:"request_timeout_secs".into(),type_hint:"integer".into(),description:"Whole connect/head/body deadline1..30 seconds for negotiation and each request".into(),required:false,example:json!(10),default:Some(json!(super::DEFAULT_TIMEOUT_SECS))}
    ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).well_known_port(2375).implementation("Negotiated read-only Engine API over HTTP TCP and native Unix sockets, typed bounded JSON schemas").llm_control("Selected read operations, native Docker filters, typed responses/errors and generic memory").e2e_testing("tests/client/docker: independent Docker daemon over Unix/TCP relay, NetGet pair, handler paths, schema/bounds/cancellation; existing server real Docker CLI tests").notes("Read-only selected API1.24..1.47 fields; newer wire fields omitted. No lifecycle mutations, image pulls, logs/attach/exec streams, Docker contexts, credential files, proxy, redirects, TLS/HTTPS or Windows named pipes. Browser HTTP TCP only. Native unix:///absolute/socket returns unspecified socket metadata0.0.0.0:0; actual endpoint remains in connected event. Body4MiB, arrays4096, object fields256, text16KiB, nesting32/nodes65536; one request, queues8,4 followups. API ping advertises maximum only, minimum incompatibility is a typed daemon error. Existing server read-only501 behavior retained.").max_inbound_bytes(super::schema::MAX_BODY).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","base_stack":"docker","protocol":"docker","remote_addr":"127.0.0.1:2375","instruction":"List containers and summarize their states"});
        let mut fixed = llm.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"docker_connected","handler":{"type":"static","actions":[{"type":"docker_request","operation":"containers","all":true}]}},{"event_pattern":"*","handler":{"type":"static","actions":[]}}]);
        let mut script = fixed.clone();
        script["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json, sys\njson.dump({'actions':[{'type':'docker_request','operation':'containers','all':True}]},sys.stdout)"});
        crate::llm::actions::StartupExamples::new(llm, script, fixed)
    }
}
impl Client for DockerClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, value: Value) -> Result<ClientActionResult> {
        match value["type"].as_str() {
            Some("docker_request") => {
                super::request(&value, super::DEFAULT_API_VERSION)?;
                Ok(ClientActionResult::Custom {
                    name: "docker_request".into(),
                    data: value,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("unknown Docker client action"),
        }
    }
}

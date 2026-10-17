use super::record;
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
pub struct FastcgiProtocol;
impl FastcgiProtocol {
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
        log_template: Some(LogTemplate::new().with_info(format!("-> FastCGI {name}"))),
    }
}

fn respond_action() -> ActionDefinition {
    action(
        "fastcgi_respond",
        "Answer the request the web server forwarded. Rust writes the CGI response (Status line, headers, body) as STDOUT records, then END_REQUEST.",
        vec![
            parameter("status", "number", "HTTP status the web server should send, 100 to 599; required, so an answer never defaults to success", true),
            parameter("headers", "object", "Response headers as name → value, e.g. {\"Content-Type\": \"application/json\"}; Status is set by Rust", false),
            parameter("body", "string", "Response body as text, or hex when body_encoding is hex (up to 1 MiB)", false),
            parameter("body_encoding", "string", "utf8 (default) or hex for binary bodies", false),
            parameter("stderr", "string", "Optional diagnostic line sent as FCGI_STDERR; web servers write it to their error log", false),
        ],
        json!({"type":"fastcgi_respond","status":200,"headers":{"Content-Type":"text/plain"},"body":"Hello from NetGet"}),
    )
}

pub static REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "fastcgi_request",
        "A complete Responder request from the web server (all PARAMS and STDIN received)",
        respond_action().example.clone(),
    )
    .with_parameters(vec![
        parameter(
            "request_id",
            "number",
            "FastCGI request id on this connection",
            true,
        ),
        parameter("method", "string", "REQUEST_METHOD, e.g. GET or POST", true),
        parameter(
            "request_uri",
            "string",
            "REQUEST_URI as the client sent it",
            false,
        ),
        parameter(
            "script_name",
            "string",
            "SCRIPT_NAME: the script path the web server mapped the request to",
            false,
        ),
        parameter(
            "path_info",
            "string",
            "PATH_INFO: extra path after the script name, when the web server splits one",
            false,
        ),
        parameter(
            "query_string",
            "string",
            "QUERY_STRING: the URL query without the leading ?",
            false,
        ),
        parameter("content_type", "string", "CONTENT_TYPE of the body", false),
        parameter(
            "headers",
            "object",
            "HTTP request headers from the HTTP_* params, lower-case names",
            true,
        ),
        parameter(
            "params",
            "object",
            "Every CGI param the web server sent",
            true,
        ),
        parameter(
            "body",
            "string",
            "Request body (STDIN) as text, or hex when body_encoding is hex",
            true,
        ),
        parameter(
            "body_encoding",
            "string",
            "How body is written: utf8 when the bytes were valid UTF-8 text, hex otherwise",
            true,
        ),
        parameter(
            "keep_conn",
            "boolean",
            "Whether the web server keeps the connection for more requests",
            true,
        ),
    ])
    .with_actions(vec![respond_action()])
});

impl Protocol for FastcgiProtocol {
    fn protocol_name(&self) -> &'static str {
        "FastCGI"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>FastCGI"
    }
    fn description(&self) -> &'static str {
        "FastCGI 1.0 application (Responder role) behind a web server such as nginx"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["fastcgi", "fcgi", "php-fpm", "cgi", "responder"]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![respond_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![REQUEST_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "idle_timeout_secs".into(),
            type_hint: "integer".into(),
            description: "Seconds a connection may sit between records before it is closed".into(),
            required: false,
            example: json!(120),
            default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Hand-written FastCGI 1.0 record codec (BEGIN/ABORT/END_REQUEST, PARAMS, STDIN, STDOUT, STDERR, GET_VALUES, UNKNOWN_TYPE); Responder role; CGI response built by Rust")
            .llm_control("The status, headers and body of every request the web server forwards")
            .e2e_testing("tests/server/fastcgi: nginx (independent FastCGI client) forwards GET, POST bodies, large responses and keep-alive requests; raw records for management, abort, multiplexing and bounds")
            .notes("Responder role only (Authorizer and Filter answer UNKNOWN_ROLE). One request at a time per connection (FCGI_MPXS_CONNS 0; a concurrent BEGIN gets CANT_MPX_CONN). PARAMS 64 KiB, STDIN 1 MiB. No storage: the handler supplies every response.")
            .request_only("FastCGI answers each request the web server forwards; nothing is pushed")
            .answers_on_failure()
            .max_inbound_bytes(record::MAX_BODY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "FastCGI app on port 9000 that answers every request with a JSON greeting"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"fastcgi","port":9000,"instruction":"Answer every page with a short HTML greeting"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"fastcgi_request","handler":{"type":"static","actions":[respond_action().example]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'fastcgi_respond','status':200,'body':'you asked for '+e['request_uri']}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Web & File"
    }
}

impl Server for FastcgiProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("fastcgi_respond") => {
                check_respond(&v)?;
                Ok(ActionResult::Custom {
                    name: "fastcgi_respond".into(),
                    data: v,
                })
            }
            _ => bail!("Unknown FastCGI server action"),
        }
    }
}

pub fn check_respond(v: &Value) -> Result<()> {
    ensure!(
        v["status"]
            .as_u64()
            .is_some_and(|s| (100..=599).contains(&s)),
        "fastcgi_respond requires an explicit status of 100..=599"
    );
    record::check_headers(v.get("headers"))?;
    record::decode_body(v)?;
    if let Some(e) = v.get("stderr").filter(|e| !e.is_null()) {
        ensure!(
            e.as_str().is_some_and(|e| e.len() <= 4096),
            "stderr must be a string of at most 4096 bytes"
        );
    }
    Ok(())
}

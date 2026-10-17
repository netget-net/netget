use super::wire;
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{EventType, SpawnContext};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct IcapProtocol;
impl IcapProtocol {
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
        "icap_response" => LogTemplate::new().with_info("-> ICAP {verdict} {status}"),
        _ => LogTemplate::new().with_info(format!("-> ICAP {name} {{service}}")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}

pub const HEADERS_HELP: &str = "[[name, value], ...] (or an object)";

fn response_action() -> ActionDefinition {
    action(
        "icap_response",
        "Decide the pending REQMOD/RESPMOD. Rust frames the ICAP response, ISTag and Encapsulated offsets and chunks the body.",
        vec![
            parameter("verdict", "string", "no_modification (204 when the client allows it, else the original echoed), modify, block (an HTTP 403 page), or error (an ICAP error status)", true),
            parameter("http_request", "object", &format!("modify on REQMOD only: the request to forward instead {{method, uri, version, headers: {HEADERS_HELP}}}"), false),
            parameter("http_response", "object", &format!("modify: the HTTP response to deliver {{status, reason, headers: {HEADERS_HELP}}} (on REQMOD this answers the client instead of forwarding)"), false),
            parameter("body_text", "string", "Body for a modified message or a block page (UTF-8 text; Rust sets Content-Length)", false),
            parameter("status", "number", "error: ICAP status 400, 403, 404, 500 or 503", false),
        ],
        json!({"type":"icap_response","verdict":"block","body_text":"Blocked by policy"}),
    )
}

pub static REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "icap_request",
        "A complete REQMOD or RESPMOD (preview already continued, body bounded). Decide whether the HTTP message passes, is changed or is blocked.",
        json!({"type":"icap_response","verdict":"no_modification"}),
    )
    .with_parameters(vec![
        parameter("method", "string", "REQMOD (an HTTP request on its way to the origin) or RESPMOD (a response on its way to the client)", true),
        parameter("service", "string", "ICAP service name from the request URI", true),
        parameter("http_request", "object", "The encapsulated HTTP request {method, uri, version, headers}, when present", false),
        parameter("http_response", "object", "The encapsulated HTTP response {version, status, reason, headers}, when present", false),
        parameter("body_text", "string", "The encapsulated body when it is UTF-8", false),
        parameter("body_binary", "boolean", "true when the body is not UTF-8 (only body_bytes is given)", false),
        parameter("body_bytes", "number", "Body size in bytes", false),
        parameter("allow_204", "boolean", "true when the client accepts 204 No Content for an unmodified message", true),
        parameter("icap_headers", "array", "ICAP request headers as [[name, value]]", true),
    ])
    .with_actions(vec![response_action()])
});

impl Protocol for IcapProtocol {
    fn protocol_name(&self) -> &'static str {
        "ICAP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>ICAP"
    }
    fn description(&self) -> &'static str {
        "ICAP content adaptation server (RFC 3507): REQMOD/RESPMOD decisions by the handler"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "icap",
            "rfc3507",
            "content filtering",
            "antivirus",
            "dlp",
            "proxy adaptation",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![response_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![REQUEST_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "services".into(),
                type_hint: "array".into(),
                description: "Services this server offers, each {name, methods: [REQMOD, RESPMOD]}; OPTIONS answers come from this list".into(),
                required: false,
                example: json!([{"name":"avscan","methods":["RESPMOD"]},{"name":"urlfilter","methods":["REQMOD"]}]),
                default: Some(json!([{"name": super::DEFAULT_SERVICE, "methods": ["REQMOD", "RESPMOD"]}])),
            },
            ParameterDefinition {
                name: "preview_bytes".into(),
                type_hint: "number".into(),
                description: "Preview size advertised in OPTIONS (0..=65536); Rust always continues a preview to the full body before deciding".into(),
                required: false,
                example: json!(1024),
                default: Some(json!(super::DEFAULT_PREVIEW)),
            },
            ParameterDefinition {
                name: "idle_timeout_secs".into(),
                type_hint: "number".into(),
                description: "Seconds (1..=86400) a persistent connection may wait between requests".into(),
                required: false,
                example: json!(300),
                default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(1344)
            .implementation("Native RFC 3507 framing over Tokio TCP: Encapsulated offsets, embedded HTTP heads, chunked bodies with preview and 100 Continue, persistent connections; OPTIONS answered from configuration")
            .llm_control("Whether each REQMOD/RESPMOD passes unmodified, is rewritten, is blocked with a page, or fails with an ICAP error")
            .e2e_testing("tests/server/icap: c-icap 0.6.5's c-icap-client (independent) sends OPTIONS, REQMOD and RESPMOD with and without preview; framing and bound tests")
            .notes("No scanning engine: decisions come from the handler. Bodies are bounded at 1 MiB and handed over as text when UTF-8 (binary bodies by size only). 206 partial responses and ICAP over TLS are not implemented. A handler failure is ICAP 500, never a pass.")
            .request_only("ICAP answers each request on its connection; nothing is sent unprompted")
            .answers_on_failure()
            .max_inbound_bytes(wire::MAX_BODY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "ICAP server on port 1344 that blocks responses containing the word EICAR"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"icap","port":1344,"instruction":"Block any response body containing EICAR; pass everything else"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"icap_request","handler":{"type":"static","actions":[{"type":"icap_response","verdict":"no_modification"}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"icap_request","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nbad='EICAR' in (e.get('body_text') or '')\nprint(json.dumps({'actions':[{'type':'icap_response','verdict':'block' if bad else 'no_modification'}]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Security"
    }
}

impl Server for IcapProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("icap_response") => {
                validate(&v)?;
                Ok(ActionResult::Custom {
                    name: "icap_response".into(),
                    data: v,
                })
            }
            _ => bail!("Unknown ICAP server action"),
        }
    }
}

pub fn validate(v: &Value) -> Result<()> {
    let verdict = v["verdict"].as_str().context("verdict is required")?;
    match verdict {
        "no_modification" | "block" => {}
        "modify" => {
            ensure!(
                !v["http_request"].is_null() || !v["http_response"].is_null(),
                "modify needs http_request or http_response"
            );
            if !v["http_request"].is_null() {
                wire::request_head(&v["http_request"])?;
            }
            if !v["http_response"].is_null() {
                wire::response_head(&v["http_response"])?;
            }
        }
        "error" => {
            let s = v["status"].as_u64().context("error needs status")?;
            ensure!(
                matches!(s, 400 | 403 | 404 | 500 | 503),
                "status must be 400, 403, 404, 500 or 503"
            );
        }
        other => bail!("unknown verdict '{other}'"),
    }
    if let Some(b) = v.get("body_text").filter(|b| !b.is_null()) {
        ensure!(
            b.as_str().context("body_text must be a string")?.len() <= wire::MAX_BODY_BYTES,
            "body_text exceeds the body bound"
        );
    }
    Ok(())
}

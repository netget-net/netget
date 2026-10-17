use super::query;
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
pub struct RdapProtocol;
impl RdapProtocol {
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
        "rdap_response" => LogTemplate::new().with_info(
            "-> RDAP response not_found={not_found} redirect={redirect} results={results_len}",
        ),
        "rdap_query" => LogTemplate::new().with_info("-> RDAP {query_type} {value}"),
        _ => LogTemplate::new().with_info(format!("-> RDAP {name}")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}

fn response_action() -> ActionDefinition {
    action(
        "rdap_response",
        "Answer the pending RDAP query. Rust sets Content-Type application/rdap+json, adds rdap_level_0 to rdapConformance and wraps search results. Supply exactly one of: object (lookups and help), results (searches), not_found=true (404), error {code,title,description}, redirect (lookups: an http(s) URL of the authoritative server).",
        vec![
            parameter("object", "object", "RFC 9083 object whose objectClassName matches the query: domain, nameserver, ip network, autnum or entity; for help, an object with notices", false),
            parameter("results", "array", "Search results, each an object with the matching objectClassName", false),
            parameter("not_found", "boolean", "true for a 404 Not Found error response", false),
            parameter("error", "object", "{code: 400|403|404|422|429|500|501|503, title, description: [text]}", false),
            parameter("redirect", "string", "Referral URL for a lookup this server is not authoritative for (302)", false),
        ],
        json!({"type":"rdap_response","object":{"objectClassName":"domain","ldhName":"example.com","handle":"EX-1","status":["active"],"events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"}]}}),
    )
}

pub static QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("rdap_query", "A well-formed RFC 9082 lookup, search or help query. There is no registry data in Rust: the handler answers.", response_action().example.clone())
        .with_parameters(vec![
            parameter("query_type", "string", "domain, nameserver, ip, autnum, entity, domains, nameservers, entities or help", true),
            parameter("value", "string", "Normalized lookup value (lower-case name, canonical IP or CIDR, decimal ASN, entity handle) or search pattern (may contain *)", false),
            parameter("search_parameter", "string", "For searches: name, nsLdhName, nsIp, ip, fn or handle", false),
            parameter("method", "string", "GET, or HEAD (existence check: the body is not sent)", true),
        ])
        .with_actions(vec![response_action()])
});

impl Protocol for RdapProtocol {
    fn protocol_name(&self) -> &'static str {
        "RDAP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>RDAP"
    }
    fn description(&self) -> &'static str {
        "RDAP registration data server (RFC 7480/9082/9083) with handler-chosen records"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "rdap",
            "rfc9082",
            "rfc9083",
            "registration data",
            "whois replacement",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![response_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![QUERY_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "base_path".into(),
            type_hint: "string".into(),
            description: "Path prefix the RDAP queries live under, e.g. /rdap; requests outside it are 404 without a handler call".into(),
            required: false,
            example: json!("/rdap"),
            default: Some(json!(super::query::DEFAULT_BASE_PATH)),
        }]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("hyper HTTP/1.1; RFC 9082 paths parsed and normalized in Rust before any handler call; RFC 9083 envelope (rdapConformance, objectClassName, search result members, error objects) enforced on every answer")
            .llm_control("The registration objects, search results, not-found and error answers, and referrals")
            .e2e_testing("tests/server/rdap: OpenRDAP 0.10.2 and ICANN rdap 1.0.0 (independent clients) query lookups, searches, help and errors; malformed paths and bounds")
            .notes("Plain HTTP (put TLS in front for production). No registry storage, bootstrap service, authentication, IDN U-label conversion or jCard validation. GET and HEAD only. 1 MiB responses, 1000 search results, 255-byte query values.")
            .request_only("RDAP answers each HTTP request; nothing is sent unprompted")
            .answers_on_failure()
            .max_inbound_bytes(super::MAX_HEADER_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "RDAP server that knows example.com, registered 1995, status active"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"rdap","port":8080,"instruction":"Registry for example.com only; everything else is not found"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"rdap_query","handler":{"type":"static","actions":[{"type":"rdap_response","not_found":true}]}}]);
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"rdap_query","handler":{"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nif e['query_type']=='domain' and e.get('value')=='example.com':\n    a={'type':'rdap_response','object':{'objectClassName':'domain','ldhName':'example.com'}}\nelse:\n    a={'type':'rdap_response','not_found':True}\nprint(json.dumps({'actions':[a]}))"}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Directory"
    }
}

impl Server for RdapProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        match v["type"].as_str() {
            Some("rdap_response") => {
                ensure!(
                    query::json_ok(&v),
                    "rdap_response exceeds the RDAP response bounds"
                );
                Ok(ActionResult::Custom {
                    name: "rdap_response".into(),
                    data: v,
                })
            }
            _ => bail!("Unknown RDAP server action"),
        }
    }
}

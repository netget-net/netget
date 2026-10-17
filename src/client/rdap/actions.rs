use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::rdap::actions::{action, parameter};
use crate::server::rdap::query::Query;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct RdapClientProtocol;
impl RdapClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn query_action() -> ActionDefinition {
    action(
        "rdap_query",
        "Send one RDAP query. Rust validates and encodes the RFC 9082 path, asks for application/rdap+json and checks the RFC 9083 envelope before raising rdap_response.",
        vec![
            parameter("query_type", "string", "domain, nameserver, ip, autnum, entity, domains, nameservers, entities or help", true),
            parameter("value", "string", "Lookup value (example.com, 192.0.2.0/24, 64496, a handle) or search pattern such as exa*.com", false),
            parameter("search_parameter", "string", "For searches: name, nsLdhName, nsIp (domains); name, ip (nameservers); fn, handle (entities). Default: the first", false),
        ],
        json!({"type":"rdap_query","query_type":"domain","value":"example.com"}),
    )
}
fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Stop this RDAP client",
        vec![],
        json!({"type":"disconnect"}),
    )
}
fn actions() -> Vec<ActionDefinition> {
    vec![query_action(), disconnect_action()]
}

pub static READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "rdap_ready",
        "The client is ready to query the RDAP server at base_url",
        query_action().example.clone(),
    )
    .with_parameters(vec![parameter(
        "base_url",
        "string",
        "The RDAP base URL queries are sent to",
        true,
    )])
    .with_actions(actions())
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("rdap_response", "The server's answer to the last query, envelope already checked", disconnect_action().example.clone())
        .with_parameters(vec![
            parameter("query_type", "string", "The query's type", true),
            parameter("value", "string", "The query's normalized value", false),
            parameter("status", "number", "HTTP status code of the answer: 200 found, 404 not found, 3xx referral, other 4xx/5xx errors", true),
            parameter("object", "object", "200: the lookup's RDAP object, or the search response with its *SearchResults member", false),
            parameter("error", "object", "4xx/5xx: the RFC 9083 error object (errorCode, title, description) if the server sent one", false),
            parameter("redirect", "string", "3xx: the Location the server referred the query to (not followed)", false),
        ])
        .with_actions(actions())
});

impl Protocol for RdapClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "RDAP"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>RDAP"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["rdap", "rfc9082", "registration data", "whois"]
    }
    fn description(&self) -> &'static str {
        "RDAP client issuing structured lookups and searches with envelope validation"
    }
    fn get_async_actions(&self, _: &crate::state::app_state::AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![READY_EVENT.clone(), RESPONSE_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "base_path".into(),
                type_hint: "string".into(),
                description: "Path prefix of the server's RDAP service, e.g. /rdap".into(),
                required: false,
                example: json!("/rdap"),
                default: Some(json!(crate::server::rdap::query::DEFAULT_BASE_PATH)),
            },
            ParameterDefinition {
                name: "https".into(),
                type_hint: "boolean".into(),
                description: "Use https:// with certificate verification instead of plain http://"
                    .into(),
                required: false,
                example: json!(true),
                default: Some(json!(super::DEFAULT_HTTPS)),
            },
            ParameterDefinition {
                name: "timeout_secs".into(),
                type_hint: "number".into(),
                description: "Seconds (1..=120) each query may take".into(),
                required: false,
                example: json!(15),
                default: Some(json!(super::TIMEOUT.as_secs())),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Shared http_fetch client (reqwest natively, no redirect following); RFC 9082 paths built and normalized by the server's own parser; RFC 9083 envelope checked on every 200")
            .llm_control("Which lookups and searches to issue and what to make of each answer, error or referral")
            .e2e_testing("tests/client/rdap: ICANN rdap-srv 1.0.0 (independent server) for lookups, search, help, not-found and redirect; NetGet pair and malformed-server checks")
            .notes("No bootstrap (RFC 9224): the server is the one given. Redirects are reported, not followed. 1 MiB responses. One query at a time.")
            .max_inbound_bytes(crate::server::rdap::query::MAX_BODY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Ask the RDAP server at 127.0.0.1:8080 who registered example.com"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"rdap","remote_addr":"127.0.0.1:8080","instruction":"Look up example.com"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"rdap_ready","handler":{"type":"static","actions":[{"type":"rdap_query","query_type":"domain","value":"example.com"}]}},
            {"event_pattern":"rdap_response","handler":{"type":"static","actions":[]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json\nprint(json.dumps({'actions':[{'type':'rdap_query','query_type':'domain','value':'example.com'}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Directory"
    }
}

impl Client for RdapClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("rdap_query") => {
                Query::from_action(&v)?;
                Ok(ClientActionResult::Custom {
                    name: "rdap_query".into(),
                    data: v,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown RDAP client action"),
        }
    }
}

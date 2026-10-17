use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct PrometheusClientProtocol;
impl PrometheusClientProtocol {
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
fn scrape() -> ActionDefinition {
    ActionDefinition{name:"scrape_metrics".into(),description:"GET metrics from this exporter's origin, negotiate text 0.0.4 or OpenMetrics 1.0.0 and parse families/samples. No raw body or PromQL service.".into(),parameters:vec![
        p("path","string","Optional origin path/query; defaults to startup metrics_path",false),
        p("format","string","auto (prefer OpenMetrics with text fallback), text, or openmetrics; default auto",false),
    ],example:json!({"type":"scrape_metrics","format":"auto"}),log_template: Some(LogTemplate::new().with_info("Scrape Prometheus exporter metrics"))}
}
fn disconnect() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".into(),
        description: "Cancel the scrape and close this logical client".into(),
        parameters: vec![],
        example: json!({"type":"disconnect"}),
        log_template: Some(
            LogTemplate::new().with_info("Cancel Prometheus scrape and close exporter client"),
        ),
    }
}
fn actions() -> Vec<ActionDefinition> {
    vec![scrape(), disconnect()]
}
fn event(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, scrape().example)
        .with_parameters(params)
        .with_actions(actions())
}
pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "prometheus_connected",
        "Exporter client ready; explicitly request a scrape",
        vec![
            p("origin", "string", "HTTP(S) exporter origin", true),
            p("metrics_path", "string", "Default scrape path/query", true),
        ],
    )
});
pub static METRICS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("prometheus_metrics","Complete, parsed exposition from one successful scrape",vec![
    p("request","object","Typed originating action",true),p("path","string","Scraped path/query",true),
    p("format","string","text or openmetrics from Content-Type",true),p("content_type","string","Exporter Content-Type",true),
    p("sample_count","integer","Number of samples in the complete parsed exposition",true),
    p("metrics","array","Families {name,type,help?,unit?,samples:[{name,suffix,labels,value,timestamp_ms? or timestamp_seconds?,exemplar?}]}; finite values are numbers, NaN/+Inf/-Inf are strings. Text timestamps are integer milliseconds; OpenMetrics and exemplar timestamps are seconds. Counter family names differ by format.",true),
])
});
pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("prometheus_scrape_error","Scrape failed; no partial metrics are accepted. The client remains available for a new request",vec![p("request","object","Originating action",true),p("path","string","Requested exporter path and query string",true),p("error","string","Transport, HTTP, format or parse refusal",true)])
});
impl Protocol for PrometheusClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Prometheus"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Prometheus"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["prometheus", "openmetrics", "exporter", "metrics"]
    }
    fn description(&self) -> &'static str {
        "Scrape and parse structured exporter metrics"
    }
    fn group_name(&self) -> &'static str {
        "AI & API"
    }
    fn example_prompt(&self) -> &'static str {
        "Scrape Prometheus metrics from localhost:9100"
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
            METRICS_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
        ParameterDefinition{name:"metrics_path".into(),type_hint:"string".into(),description:"Origin path/query used when a scrape action omits path".into(),required:false,example:json!("/metrics"),default:Some(json!(super::DEFAULT_PATH))},
        ParameterDefinition{name:"scrape_timeout_secs".into(),type_hint:"integer".into(),description:"Whole scrape deadline, 1..30 seconds; sent in X-Prometheus-Scrape-Timeout-Seconds".into(),required:false,example:json!(10),default:Some(json!(super::DEFAULT_TIMEOUT_SECS))},
    ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).well_known_port(9100)
        .implementation("Bounded HTTP exporter requests and typed text/OpenMetrics parser")
        .llm_control("Explicit scrape path and format; handle typed family/sample results or scrape errors")
        .e2e_testing("tests/client/prometheus: independent Prometheus exporter, NetGet exporter pair, negotiation/parser/bounds/cancellation and event handlers")
        .notes("Exporter scraping only; no PromQL query API, remote write, protobuf/native histograms, target discovery, scrape scheduler, redirects, compression or persistent metric store. Legacy metric/label names negotiated with escaping=underscores. Native HTTPS verifies system roots; browser HTTP only. Body4MiB, samples20000, families4096, labels64, text16KiB; one active scrape, queues8 and4 handler followups. Manual handlers do not block injection/disconnect.")
        .max_inbound_bytes(super::exposition::MAX_BODY).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","base_stack":"prometheus","protocol":"prometheus","remote_addr":"127.0.0.1:9100","instruction":"Scrape metrics once and explain them"});
        let mut fixed = llm.clone();
        fixed["event_handlers"] = json!([{"event_pattern":"prometheus_connected","handler":{"type":"static","actions":[scrape().example]}},{"event_pattern":"*","handler":{"type":"static","actions":[]}}]);
        let mut script = fixed.clone();
        script["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json, sys\njson.dump({'actions':[{'type':'scrape_metrics','format':'auto'}]},sys.stdout)"});
        crate::llm::actions::StartupExamples::new(llm, script, fixed)
    }
}
impl Client for PrometheusClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("scrape_metrics") => {
                super::request(&v, super::DEFAULT_PATH)?;
                Ok(ClientActionResult::Custom {
                    name: "scrape_metrics".into(),
                    data: v,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("unknown Prometheus client action"),
        }
    }
}

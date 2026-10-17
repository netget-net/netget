//! Prometheus exporter actions.
//!
//! One event, two actions, all structured. The model never writes exposition text: it names
//! families, types, help strings, labels and values, and [`super::exposition`] validates and
//! renders them. That is the whole point of the protocol here — a scraper rejects a target over
//! one malformed line, so the part a model is worst at (byte-exact text framing, escaping,
//! suffix conventions) is the part NetGet owns.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

use super::exposition::MetricFamilies;

/// `GET /metrics` — a scraper wants the target's current metrics.
pub static PROMETHEUS_SCRAPE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "prometheus_scrape",
        "A Prometheus server (or promtool, or any metrics collector) scraped /metrics. Answer \
         with the metrics this target exposes right now. Counters only ever go up between \
         scrapes; keep values consistent with earlier answers if memory holds them.",
        example_metrics_action(),
    )
    .with_actions(vec![send_metrics_action(), send_scrape_error_action()])
});

/// Prometheus exporter protocol handler.
pub struct PrometheusProtocol;

impl PrometheusProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PrometheusProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Protocol for PrometheusProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        Vec::new()
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![send_metrics_action(), send_scrape_error_action()]
    }

    fn protocol_name(&self) -> &'static str {
        "Prometheus"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![PROMETHEUS_SCRAPE_EVENT.clone()]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>PROMETHEUS"
    }

    fn keywords(&self) -> Vec<&'static str> {
        // Specific on purpose: "metrics" alone collides with every monitoring-flavoured prompt.
        vec![
            "prometheus",
            "exporter",
            "node_exporter",
            "/metrics",
            "openmetrics",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };

        ProtocolMetadataV2::builder()
            // Beta on evidence: tests/server/prometheus/real_client_test.rs drives the
            // Prometheus project's own promtool (parse + lint, with a negative control) and a
            // real prometheus scraping in both negotiated formats and answering PromQL, and
            // both binaries hard-fail when absent. Not Stable: one project's tools are the only
            // peers (promtool and prometheus share the same parser code), there is no fuzz
            // target and no pcap-oracle test, and protobuf/native histograms are absent.
            .state(DevelopmentState::Beta)
            .well_known_port(9100)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation(
                "hyper HTTP/1.1. GET /metrics raises prometheus_scrape; the model answers with \
                 structured families and NetGet renders the exposition itself (text format \
                 0.0.4, or OpenMetrics 1.0.0 when the Accept header prefers it) - names \
                 validated, label values and help escaped, counters suffixed _total, histogram \
                 buckets sorted with a +Inf bucket and _count guaranteed. GET / is a static \
                 HTML link page; HEAD /metrics answers headers without the model.",
            )
            .llm_control(
                "Every scrape: which metric families exist, their types, help text, labels and \
                 values (send_metrics), or a refusal (send_scrape_error). NetGet stores no \
                 values between scrapes; a static handler serves a fixed set with no LLM call.",
            )
            .e2e_testing(
                "tests/server/prometheus/real_client_test.rs - promtool check metrics (the \
                 Prometheus project's own parser and linter) reads bodies NetGet served and \
                 must exit 0; a deliberately broken exposition is the negative control that \
                 proves promtool rejects. A real prometheus binary scrapes NetGet in both \
                 negotiated formats and its query API must report up == 1 and the served \
                 sample. Both binaries HARD FAIL when absent. e2e_test.rs covers the mocked \
                 model path; exposition_test.rs the renderer.",
            )
            .notes(
                "Exposition formats: text 0.0.4 and OpenMetrics 1.0.0 (negotiated from \
                 Accept). Not implemented: protobuf exposition, native histograms, exemplars, \
                 _created series, # UNIT lines, gzip, UTF-8 metric names (legacy names only), \
                 federation's match[] filtering, and any authentication. Invalid families from \
                 the model are refused by the executor (the reason is in the log and the \
                 access log) and the scrape is answered 500, never a partial body.",
            )
            .max_inbound_bytes(super::MAX_REQUEST_BODY_BYTES)
            // LLM failure: 503 + Retry-After when the backend is saturated, 500 otherwise, each
            // with a fixed text/plain category. Prometheus records the status as the scrape
            // error and never reads the body as metrics.
            .answers_on_failure()
            .request_only("Prometheus scraping is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Prometheus exporter (/metrics) whose metrics the model invents"
    }

    fn example_prompt(&self) -> &'static str {
        "Be a Prometheus exporter on port 9100 for a web server: request counts by status code, \
         an in-flight gauge and a request latency histogram"
    }

    fn group_name(&self) -> &'static str {
        "AI & API"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            json!({
                "type": "open_server",
                "port": 9100,
                "base_stack": "prometheus",
                "instruction": "Prometheus exporter for a web server. Expose \
                                http_requests_total by method and status (GET 200 grows by \
                                about 50 per scrape, 500s are rare), an in-flight requests \
                                gauge between 0 and 10, and a request latency histogram in \
                                seconds."
            }),
            json!({
                "type": "open_server",
                "port": 9100,
                "base_stack": "prometheus",
                "event_handlers": [{
                    "event_pattern": "prometheus_scrape",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json, sys, time\nevent = json.load(sys.stdin)['event']\nfmt = event.get('format', 'text')\nprint(json.dumps({'actions': [{'type': 'send_metrics', 'metrics': [{'name': 'app_time_seconds', 'type': 'gauge', 'help': 'Seconds since the epoch at scrape time', 'samples': [{'value': int(time.time())}]}, {'name': 'app_scrapes_total', 'type': 'counter', 'help': 'Scrapes served, by negotiated format', 'samples': [{'labels': {'format': fmt}, 'value': 1}]}]}]}))"
                    }
                }]
            }),
            json!({
                "type": "open_server",
                "port": 9100,
                "base_stack": "prometheus",
                "event_handlers": [{
                    "event_pattern": "prometheus_scrape",
                    "handler": {
                        "type": "static",
                        "actions": [example_metrics_action()]
                    }
                }]
            }),
        )
    }
}

impl Server for PrometheusProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            super::PrometheusServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "send_metrics" => {
                let metrics = action
                    .get("metrics")
                    .context("send_metrics is missing the required 'metrics' array")?;
                // Validate here, so a bad name is an action failure the log and the access log
                // record against the model's answer, not a surprise at render time.
                let families = MetricFamilies::parse(metrics)
                    .map_err(|reason| anyhow::anyhow!("send_metrics refused: {reason}"))?;
                Ok(ActionResult::Custom {
                    name: "send_metrics".to_string(),
                    data: json!({
                        "metrics": metrics,
                        "families": families.family_count(),
                        "samples": families.sample_count(),
                    }),
                })
            }
            "send_scrape_error" => {
                let status = action.get("status").and_then(|v| v.as_u64()).unwrap_or(503);
                if !(400..600).contains(&status) {
                    return Err(anyhow::anyhow!(
                        "send_scrape_error 'status' must be a 4xx or 5xx HTTP status, got {status}"
                    ));
                }
                let message = action
                    .get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("scrape refused")
                    .to_string();
                Ok(ActionResult::Custom {
                    name: "send_scrape_error".to_string(),
                    data: json!({"status": status, "message": message}),
                })
            }
            other => Err(anyhow::anyhow!("Unknown Prometheus action: {other}")),
        }
    }
}

fn example_metrics_action() -> serde_json::Value {
    json!({
        "type": "send_metrics",
        "metrics": [
            {
                "name": "http_requests_total",
                "type": "counter",
                "help": "HTTP requests served, by method and status code.",
                "samples": [
                    {"labels": {"method": "GET", "code": "200"}, "value": 1027},
                    {"labels": {"method": "GET", "code": "500"}, "value": 3}
                ]
            },
            {
                "name": "http_requests_in_flight",
                "type": "gauge",
                "help": "Requests currently being served.",
                "samples": [{"value": 4}]
            },
            {
                "name": "http_request_duration_seconds",
                "type": "histogram",
                "help": "Request latency.",
                "samples": [
                    {"suffix": "_bucket", "labels": {"le": "0.1"}, "value": 900},
                    {"suffix": "_bucket", "labels": {"le": "0.5"}, "value": 1010},
                    {"suffix": "_bucket", "labels": {"le": "+Inf"}, "value": 1030},
                    {"suffix": "_sum", "value": 81.4},
                    {"suffix": "_count", "value": 1030}
                ]
            }
        ]
    })
}

fn send_metrics_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_metrics".to_string(),
        description:
            "Answer a scrape with this target's metrics. Give structured families; NetGet \
             writes the exposition text, escapes it, appends _total to counters, sorts histogram \
             buckets and adds the +Inf bucket and _count if you leave them out. An invalid name \
             or a malformed histogram is refused and the scrape fails, so keep names to \
             letters, digits, underscores and colons."
                .to_string(),
        parameters: vec![Parameter {
            name: "metrics".to_string(),
            type_hint: "array".to_string(),
            description: "Metric families: [{\"name\": \"http_requests_total\", \"type\": \
                 counter|gauge|histogram|summary|untyped, \"help\": \"one line of text\", \
                 \"samples\": [{\"labels\": {\"k\": \"v\"}, \"value\": number or \"NaN\"/\"+Inf\", \
                 \"suffix\": \"_bucket\"|\"_sum\"|\"_count\"|\"_total\"|\"\" , \
                 \"timestamp_ms\": optional integer}]}]. A histogram's _bucket samples carry an \
                 \"le\" label (upper bound, or \"+Inf\") and are cumulative; a summary's \
                 quantile samples carry a \"quantile\" label between 0 and 1 and no suffix. \
                 Gauges and untyped samples have no suffix."
                .to_string(),
            required: true,
        }],
        example: example_metrics_action(),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Prometheus metrics ({families} families, {samples} samples)")
                .with_debug("Prometheus send_metrics: {families} families {samples} samples"),
        ),
    }
}

fn send_scrape_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_scrape_error".to_string(),
        description: "Fail this scrape on purpose - the target is down, overloaded or refuses the \
             scraper. Prometheus marks the target up=0 and shows the message as the scrape \
             error. Structurally distinct from send_metrics, so a refusal is never read as an \
             empty target."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "status".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status, 4xx or 5xx (default 503)".to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "One line of text explaining the failure".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "send_scrape_error",
            "status": 503,
            "message": "exporter is warming up"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Prometheus scrape refused ({status})")
                .with_debug("Prometheus send_scrape_error: {status} {message}"),
        ),
    }
}

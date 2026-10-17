use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{
    metadata::{DevelopmentState, ProtocolMetadataV2},
    ConnectContext, EventType,
};
use crate::server::influxdb::{
    actions::parameter,
    codec::{self, WriteBatch},
};
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct InfluxDbClientProtocol;
impl InfluxDbClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn write_action() -> ActionDefinition {
    ActionDefinition {name:"write_influx_points".into(),description:"Submit one typed InfluxDB v2 batch. Completion reports HTTP status; 204 is handler acceptance, not durable storage. No automatic retries.".into(),parameters:vec![parameter("batch","object","org,bucket,precision ns/us/ms/s(default ns),points(1..256) with measurement,tags,fields typed {type:float/integer/unsigned/boolean/string,value},optional timestamp;gzip(default false)",true)],example:json!({"type":"write_influx_points","batch":{"org":"example","bucket":"metrics","points":[{"measurement":"cpu","tags":{"host":"localhost"},"fields":{"load":{"type":"float","value":0.42}},"timestamp":1700000000000000000i64}]}}),log_template: Some(LogTemplate::new().with_info("Submit typed InfluxDB write batch"))}
}
/// The `ClientActionResult::Custom` name a query travels under.
pub const QUERY_RESULT: &str = "influx_query";
pub fn flux_action() -> ActionDefinition {
    ActionDefinition {
        name: "query_influx_flux".into(),
        description: "Run a Flux query (POST /api/v2/query). The answer arrives as influx_query_response with typed tables: each table's columns (name, Flux datatype, group-key membership) and rows of JSON values, converted from InfluxDB's annotated CSV.".into(),
        parameters: vec![
            parameter("org", "string", "Organization name the query runs in", true),
            parameter("query", "string", "The Flux script, at most 16 KiB, e.g. from(bucket:\"metrics\") |> range(start: -1h)", true),
        ],
        example: json!({"type":"query_influx_flux","org":"example","query":"from(bucket: \"metrics\") |> range(start: -1h) |> filter(fn: (r) => r._measurement == \"cpu\")"}),
        log_template: Some(LogTemplate::new().with_info("Run Flux query in org {org}")),
    }
}
pub fn influxql_action() -> ActionDefinition {
    ActionDefinition {
        name: "query_influxql".into(),
        description: "Run an InfluxQL query (GET /query, the v1-compatible API; on InfluxDB 2 the database is a bucket's DBRP mapping). Several statements may be separated by ';'. The answer arrives as influx_query_response with one entry per statement: its series (name, tags, columns, values) or its error.".into(),
        parameters: vec![
            parameter("query", "string", "The InfluxQL text, at most 16 KiB, e.g. SELECT mean(usage) FROM cpu WHERE time > now() - 1h GROUP BY host", true),
            parameter("db", "string", "Database (on InfluxDB 2, the bucket's DBRP database name)", false),
            parameter("rp", "string", "Retention policy; absent means the database default", false),
            parameter("epoch", "string", "Return times as integers in ns, u, ms, s, m or h; absent means RFC 3339 strings", false),
        ],
        example: json!({"type":"query_influxql","db":"metrics","query":"SELECT mean(usage) FROM cpu WHERE time > now() - 1h GROUP BY host"}),
        log_template: Some(LogTemplate::new().with_info("Run InfluxQL query on database {db}")),
    }
}
fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".into(),
        description: "Cancel this HTTP write session, parked handlers and an in-flight exchange"
            .into(),
        parameters: vec![],
        example: json!({"type":"disconnect"}),
        log_template: Some(
            LogTemplate::new().with_info("Cancel InfluxDB write session and active exchange"),
        ),
    }
}
pub static INFLUX_CONNECTED_EVENT: LazyLock<EventType> =
    LazyLock::new(|| {
        EventType::new(
        "influx_connected",
        "Logical HTTP write session ready; no TCP connection is opened until a validated write.",
        write_action().example,
    )
    .with_parameters(vec![parameter(
        "remote_addr",
        "string",
        "Configured HTTP origin for InfluxDB writes",
        true,
    )])
    .with_actions(vec![write_action(), flux_action(), influxql_action(), disconnect_action()])
    });
pub static INFLUX_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("influx_write_response","Typed HTTP v2 write outcome. 204 is acceptance; error contains code/message and optional partial counts/source line. Tokens/raw bodies are excluded; retry advice does not trigger retries.",write_action().example).with_parameters(vec![parameter("org","string","Submitted organization",true),parameter("bucket","string","Submitted bucket",true),parameter("point_count","number","Submitted points",true),parameter("status","number","HTTP status returned for the submitted write batch",true),parameter("error","object|null","Typed code,message,optional line/accepted_points/rejected_points",true),parameter("retry_after_seconds","number|null","Numeric retry advice",true)]).with_actions(vec![write_action(),flux_action(),influxql_action(),disconnect_action()])
});
pub static INFLUX_QUERY_RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("influx_query_response","The answer to a Flux or InfluxQL query, read into structured tables (never raw CSV). At most 1000 rows and 64 tables are reported; row_count says how many the answer held.",flux_action().example).with_parameters(vec![parameter("language","string","flux or influxql",true),parameter("query","string","The query as sent",true),parameter("org","string","Flux: the org it ran in",false),parameter("db","string","InfluxQL: the database",false),parameter("status","number","HTTP status of the answer",true),parameter("tables","array","Flux: [{result, table, columns:[{name,type,group}], rows:[[typed values]]}]",false),parameter("statements","array","InfluxQL: [{statement_id, series:[{name,tags,columns,values}]} or {statement_id, error}]",false),parameter("row_count","number","Rows in the whole answer",true),parameter("reported_rows","number","Rows this event carries",true),parameter("truncated","boolean","Rows or tables were left out of this event",true),parameter("error","object|null","Non-2xx answers: {code, message} from the server",true)]).with_actions(vec![write_action(),flux_action(),influxql_action(),disconnect_action()])
});
impl Protocol for InfluxDbClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "InfluxDB"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>InfluxDB"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["influxdb", "influxdb2", "influx-write", "flux", "influxql"]
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
    fn description(&self) -> &'static str {
        "Typed InfluxDB v2 HTTP write emitter and Flux/InfluxQL query client with explicit partial-write/error outcomes"
    }
    fn example_prompt(&self) -> &'static str {
        "Write a typed CPU metric to InfluxDB at http://localhost:8086"
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![
            write_action(),
            flux_action(),
            influxql_action(),
            disconnect_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            INFLUX_CONNECTED_EVENT.clone(),
            INFLUX_RESPONSE_EVENT.clone(),
            INFLUX_QUERY_RESPONSE_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![ParameterDefinition {
            name: "auth_token".into(),
            type_hint: "string".into(),
            description:
                "Optional printable ASCII Token credential,<=1024bytes,never exposed to handlers"
                    .into(),
            required: false,
            example: json!("collector-secret"),
            default: None,
        }]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).well_known_port(8086)
            .implementation("Native typed line protocol/gzip with owned Hyper HTTP/1.1 exchanges; Flux annotated-CSV reader and InfluxQL v1-JSON reader (src/client/influxdb/query.rs)")
            .llm_control("Connected, write-response and query-response events, ordinary memory and live injection during parked handlers or IO; a query's answer reaches handlers as typed tables and their follow-ups run")
            .e2e_testing("Official Python1.50.0 emitter; official InfluxDB 2.9.1 daemon: native writes read back, then Flux and InfluxQL queries read into typed tables (doubles, longs, booleans, quoted strings, group keys, multi-statement series, epoch, the daemon's own 400/401 refusals) and a write→query handler chain; MIT line-protocol2.2.1 decoder-backed HTTP receiver; native pair/negative/lifecycle checks")
            .notes("HTTP origin only; POST /api/v2/write: org, bucket, ns/us/ms/s precision; optional Token auth; identity/gzip. POST /api/v2/query (Flux, annotated CSV back) and GET /query (InfluxQL, v1 JSON back; on InfluxDB 2 through DBRP mappings). Bounds: 256 KiB body, 16 KiB line, 256 points, 64 tags/fields, 1024-byte names/token, 64 KiB write response, 16 KiB query, 4 MiB query answer, 1000 reported rows and 64 reported tables per event (row_count gives the whole), 256 columns, 32 KiB/64 response headers, 128-byte code/1024-byte message, 10s write and 30s query exchange, one in-flight request, 32 queued events/actions, 8 follow-up depth. An unreadable 2xx answer or an in-band Flux error is reported as an error event. Strict single separators; no CR/LF/NUL strings or trailing-backslash names. No TLS, orgID query, redirects, proxy, chunked InfluxQL, schema/persistence/retry, HTTP-date Retry-After, fuzz or pcap. Fresh TCP per request; local logical address0.0.0.0:0.").history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_client","base_stack":"influxdb","remote_addr":"http://localhost:8086","startup_params":{"auth_token":"collector-secret"},"instruction":"Write one CPU load point"}),
            json!({"type":"open_client","base_stack":"influxdb","remote_addr":"http://localhost:8086","event_handlers":[{"event_pattern":"influx_connected","handler":{"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'disconnect'}]}))"}}]}),
            json!({"type":"open_client","base_stack":"influxdb","remote_addr":"http://localhost:8086","event_handlers":[{"event_pattern":"influx_connected","handler":{"type":"static","actions":[write_action().example]}}]}),
        )
    }
}
impl Client for InfluxDbClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::InfluxDbClient::connect(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match action["type"].as_str() {
            Some("write_influx_points") => {
                let batch: WriteBatch =
                    serde_json::from_value(action.get("batch").context("batch required")?.clone())?;
                codec::encode_batch(&batch)?;
                Ok(ClientActionResult::Custom {
                    name: "write_influx_points".into(),
                    data: serde_json::to_value(batch)?,
                })
            }
            Some(kind @ ("query_influx_flux" | "query_influxql")) => {
                let spec = super::query::QuerySpec {
                    language: if kind == "query_influx_flux" {
                        super::query::Language::Flux
                    } else {
                        super::query::Language::Influxql
                    },
                    query: action["query"].as_str().context("query required")?.into(),
                    org: action["org"].as_str().map(String::from),
                    db: action["db"].as_str().map(String::from),
                    rp: action["rp"].as_str().map(String::from),
                    epoch: action["epoch"].as_str().map(String::from),
                };
                spec.validate()?;
                Ok(ClientActionResult::Custom {
                    name: QUERY_RESULT.into(),
                    data: serde_json::to_value(spec)?,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("unknown InfluxDB emitter action"),
        }
    }
}

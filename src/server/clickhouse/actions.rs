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
pub struct ClickhouseProtocol;
impl ClickhouseProtocol {
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
        "clickhouse_result" => LogTemplate::new()
            .with_info("-> ClickHouse result {preview(columns,80)} {preview(rows,80)}"),
        "clickhouse_exception" => {
            LogTemplate::new().with_info("-> ClickHouse exception {code}: {message}")
        }
        "clickhouse_query" => {
            LogTemplate::new().with_info("-> ClickHouse query {preview(query,100)}")
        }
        _ => LogTemplate::new().with_info(format!("-> ClickHouse {name}")),
    };
    ActionDefinition {
        name: name.into(),
        description: description.into(),
        parameters,
        example,
        log_template: Some(log_template),
    }
}

pub fn columns_param() -> Parameter {
    parameter(
        "columns",
        "array",
        "[{name, type}] with types UInt8..UInt64, Int8..Int64, Float32, Float64, Bool, String, Date, DateTime or Nullable(...) of those",
        true,
    )
}

fn result_action() -> ActionDefinition {
    action(
        "clickhouse_result",
        "Answer a query with a result set. Rust sends the header block, the rows, progress and end of stream.",
        vec![
            columns_param(),
            parameter("rows", "array", "Rows as arrays in column order; Date as YYYY-MM-DD, DateTime as YYYY-MM-DD hh:mm:ss, null for Nullable", true),
        ],
        json!({"type":"clickhouse_result","columns":[{"name":"x","type":"UInt8"},{"name":"s","type":"String"}],"rows":[[1,"a"],[2,"b"]]}),
    )
}

fn ok_action() -> ActionDefinition {
    action(
        "clickhouse_ok",
        "Finish a statement that returns no rows (CREATE, DROP, SET, an accepted INSERT's data).",
        vec![],
        json!({"type":"clickhouse_ok"}),
    )
}

fn insert_action() -> ActionDefinition {
    action(
        "clickhouse_insert",
        "Accept an INSERT and describe the table's columns; the client then sends its rows, which arrive as clickhouse_insert_data.",
        vec![columns_param()],
        json!({"type":"clickhouse_insert","columns":[{"name":"id","type":"UInt32"},{"name":"name","type":"String"}]}),
    )
}

fn exception_action() -> ActionDefinition {
    action(
        "clickhouse_exception",
        "Fail the query with a ClickHouse exception the client shows as Code: N. DB::Exception: message.",
        vec![
            parameter("code", "number", "Error code, e.g. 60 UNKNOWN_TABLE, 62 SYNTAX_ERROR, 497 ACCESS_DENIED; default 1002", false),
            parameter("message", "string", "Exception message", true),
        ],
        json!({"type":"clickhouse_exception","code":60,"message":"Table default.missing does not exist"}),
    )
}

pub static QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "clickhouse_query",
        "A client ran a SQL query; answer with rows, no rows, acceptance of an INSERT, or an exception.",
        result_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("query", "string", "The SQL statement text", true),
        parameter("query_id", "string", "Query id the client set, often empty", true),
        parameter("database", "string", "Default database from the client's hello", true),
        parameter("user", "string", "User the client logged in as", true),
        parameter("settings", "object", "Settings the client sent with the query", true),
        parameter("remote_addr", "string", "Client address and port", true),
    ])
    .with_actions(vec![result_action(), ok_action(), insert_action(), exception_action()])
});

pub static INSERT_DATA_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "clickhouse_insert_data",
        "The rows of an INSERT you accepted have arrived; confirm or fail it.",
        ok_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("query", "string", "The INSERT statement", true),
        parameter(
            "columns",
            "array",
            "[{name, type}] as the client sent them",
            true,
        ),
        parameter("rows", "array", "The inserted rows, in column order", true),
        parameter("user", "string", "User the client logged in as", true),
    ])
    .with_actions(vec![ok_action(), exception_action()])
});

impl Protocol for ClickhouseProtocol {
    fn protocol_name(&self) -> &'static str {
        "ClickHouse"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>ClickHouse"
    }
    fn description(&self) -> &'static str {
        "ClickHouse native TCP server whose query results and inserts the handler decides"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "clickhouse",
            "clickhouse native",
            "olap",
            "columnar database",
            "sql",
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            result_action(),
            ok_action(),
            insert_action(),
            exception_action(),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![QUERY_EVENT.clone(), INSERT_DATA_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "user".into(),
                type_hint: "string".into(),
                description: "With password: the only user allowed to log in, checked in Rust; without both, every login is accepted".into(),
                required: false,
                example: json!("default"),
                default: None,
            },
            ParameterDefinition {
                name: "password".into(),
                type_hint: "string".into(),
                description: "With user: the password checked in Rust".into(),
                required: false,
                example: json!("secret"),
                default: None,
            },
            ParameterDefinition {
                name: "idle_timeout_secs".into(),
                type_hint: "number".into(),
                description: "Seconds a connection may stay silent between packets (1..=86400)".into(),
                required: false,
                example: json!(600),
                default: Some(json!(super::IDLE_TIMEOUT.as_secs())),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(9000)
            .implementation("ClickHouse native TCP at protocol revision 54429, hand-written: hello, ping, query with settings, external-table terminator, Data blocks with typed columns, LZ4 compressed frames with CityHash128 checksums, INSERT header and row blocks, progress, exceptions, end of stream")
            .llm_control("Each query's result (columns and rows), acceptance of DDL, the table shape for an INSERT and whether its rows are accepted, and exceptions")
            .e2e_testing("tests/server/clickhouse: raw packets and bounds; the official clickhouse-client 24.8 (with and without compression) and Python clickhouse-driver as independent clients")
            .notes("Column types: UInt8..UInt64, Int8..Int64, Float32/64, Bool, String, Date, DateTime and Nullable of those; no arrays, decimals, LowCardinality or external tables. opensrv-clickhouse was not used: it allocates from wire lengths with no bound. Strings are capped at 1 MiB, a block at 16 MiB, 1000 columns and 100000 rows; each connection may be silent idle_timeout_secs. A handler failure answers an exception (code 1002, or 202 when the backend is saturated) with a generic message, never a fabricated result.")
            .request_only("Every packet answers the client's hello, ping or query")
            .answers_on_failure()
            .max_inbound_bytes(super::wire::MAX_BLOCK_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "ClickHouse server on port 9000 with a web_events table the handler answers queries about"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_server","base_stack":"clickhouse","port":9000,"instruction":"Pretend to hold a web_events table (ts DateTime, url String, hits UInt32) and answer queries about it"});
        let mut scripted = llm.clone();
        scripted["event_handlers"] = json!([{"event_pattern":"clickhouse_query","handler":{"type":"script","language":"python","code":"import json,sys\nq=json.load(sys.stdin)['event']['query'].strip().rstrip(';')\na={'type':'clickhouse_result','columns':[{'name':'version()','type':'String'}],'rows':[['24.8.0']]} if q.lower()=='select version()' else {'type':'clickhouse_exception','code':62,'message':'Unsupported query'}\nprint(json.dumps({'actions':[a]}))"}}]);
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"clickhouse_query","handler":{"type":"static","actions":[{"type":"clickhouse_result","columns":[{"name":"x","type":"UInt8"}],"rows":[[1]]}]}}]);
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }
}

impl Server for ClickhouseProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ActionResult> {
        let name = v["type"].as_str().unwrap_or_default().to_string();
        match name.as_str() {
            "clickhouse_result" => {
                super::wire::Block::from_json(&v["columns"], &v["rows"])?;
            }
            "clickhouse_insert" => {
                let block = super::wire::Block::from_json(&v["columns"], &Value::Null)?;
                ensure!(
                    !block.columns.is_empty(),
                    "an INSERT needs at least one column"
                );
            }
            "clickhouse_exception" => {
                ensure!(v["message"].is_string(), "message must be a string");
                ensure!(
                    v.get("code").is_none_or(|c| c
                        .as_i64()
                        .is_some_and(|c| (0..=i64::from(i32::MAX)).contains(&c))),
                    "code must be a non-negative integer"
                );
            }
            "clickhouse_ok" => {}
            _ => bail!("Unknown ClickHouse server action"),
        }
        Ok(ActionResult::Custom { name, data: v })
    }
}

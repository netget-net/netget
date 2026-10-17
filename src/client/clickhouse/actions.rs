use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition,
};
use crate::protocol::{ConnectContext, EventType};
use crate::server::clickhouse::{
    actions::{action, parameter},
    wire,
};
use crate::state::app_state::AppState;
use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;

#[derive(Default)]
pub struct ClickhouseClientProtocol;
impl ClickhouseClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

fn query_action() -> ActionDefinition {
    action(
        "clickhouse_query",
        "Run a SQL statement that is not an INSERT; its rows arrive as clickhouse_result.",
        vec![parameter("query", "string", "The SQL statement text", true)],
        json!({"type":"clickhouse_query","query":"SELECT name, engine FROM system.tables LIMIT 5"}),
    )
}

fn insert_action() -> ActionDefinition {
    action(
        "clickhouse_insert",
        "Insert rows: the server describes the columns, Rust encodes the rows to match, and the outcome arrives as clickhouse_result.",
        vec![
            parameter("query", "string", "The INSERT statement without data, e.g. INSERT INTO t (id, name) VALUES", true),
            parameter("rows", "array", "Rows as arrays in the table's column order", true),
        ],
        json!({"type":"clickhouse_insert","query":"INSERT INTO events (id, name) VALUES","rows":[[1,"signup"]]}),
    )
}

fn disconnect_action() -> ActionDefinition {
    action(
        "disconnect",
        "Close the ClickHouse connection",
        vec![],
        json!({"type":"disconnect"}),
    )
}

fn actions() -> Vec<ActionDefinition> {
    vec![query_action(), insert_action(), disconnect_action()]
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "clickhouse_connected",
        "Logged in to the ClickHouse server.",
        query_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("server_name", "string", "Server name from its hello", true),
        parameter(
            "version",
            "string",
            "Server version major.minor.patch",
            true,
        ),
        parameter("revision", "number", "Protocol revision in use", true),
        parameter("timezone", "string", "Server timezone, when sent", false),
    ])
    .with_actions(actions())
});

pub static RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "clickhouse_result",
        "The outcome of one query or insert.",
        query_action().example.clone(),
    )
    .with_parameters(vec![
        parameter("query", "string", "The statement this answers", true),
        parameter(
            "ok",
            "boolean",
            "False when the server raised an exception",
            true,
        ),
        parameter("columns", "array", "[{name, type}] of the result", false),
        parameter("rows", "array", "Result rows, in column order", false),
        parameter(
            "exception",
            "object",
            "{code, message} when ok is false",
            false,
        ),
        parameter("rows_written", "number", "For an insert: rows sent", false),
    ])
    .with_actions(actions())
});

pub fn check(v: &Value) -> Result<()> {
    let query = v["query"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("query must be a string"))?;
    ensure!(
        !query.trim().is_empty() && query.len() <= wire::MAX_STRING,
        "query must be 1 byte to 1 MiB"
    );
    match v["type"].as_str() {
        Some("clickhouse_query") => {}
        Some("clickhouse_insert") => {
            let rows = v["rows"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("rows must be an array of arrays"))?;
            ensure!(
                !rows.is_empty() && rows.len() <= wire::MAX_ROWS,
                "1 to {} rows",
                wire::MAX_ROWS
            );
            ensure!(
                rows.iter().all(Value::is_array),
                "each row must be an array"
            );
        }
        _ => bail!("Unknown ClickHouse client action"),
    }
    Ok(())
}

impl Protocol for ClickhouseClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "ClickHouse"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>ClickHouse"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["clickhouse", "clickhouse native", "olap", "sql"]
    }
    fn description(&self) -> &'static str {
        "ClickHouse native TCP client: queries and inserts"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![CONNECTED_EVENT.clone(), RESULT_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "user".into(),
                type_hint: "string".into(),
                description: "User to log in as".into(),
                required: false,
                example: json!("default"),
                default: Some(json!(super::DEFAULT_USER)),
            },
            ParameterDefinition {
                name: "password".into(),
                type_hint: "string".into(),
                description: "Password for that user".into(),
                required: false,
                example: json!("secret"),
                default: None,
            },
            ParameterDefinition {
                name: "database".into(),
                type_hint: "string".into(),
                description: "Default database; empty for the server's own default".into(),
                required: false,
                example: json!("analytics"),
                default: None,
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .well_known_port(9000)
            .implementation("ClickHouse native TCP at protocol revision 54429: hello, uncompressed queries with the external-tables terminator, Data, Progress, ProfileInfo, Totals, Extremes, Log and TableColumns packets, exceptions, and the INSERT header/data exchange")
            .llm_control("Which statements to run and rows to insert, and what to do with each result")
            .e2e_testing("tests/client/clickhouse: NetGet's own server; the official ClickHouse server 24.8 as the independent peer")
            .notes("Result columns are decoded for integers, floats, Bool, String, Date, DateTime and Nullable of those; a result with another type ends the session, because its bytes cannot be skipped without knowing their layout. Strings are capped at 1 MiB, blocks at 16 MiB, 100000 rows. Use clickhouse_insert, not clickhouse_query, for INSERT.")
            .max_inbound_bytes(wire::MAX_BLOCK_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to ClickHouse at 127.0.0.1:9000 and list the tables in the default database"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"type":"open_client","protocol":"clickhouse","remote_addr":"127.0.0.1:9000","instruction":"List the tables and count rows in each"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern":"clickhouse_connected","handler":{"type":"static","actions":[{"type":"clickhouse_query","query":"SELECT version()"}]}},
            {"event_pattern":"clickhouse_result","handler":{"type":"static","actions":[{"type":"disconnect"}]}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1]["handler"] = json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'clickhouse_query','query':'SHOW TABLES'}] if e['query']=='SELECT version()' else [{'type':'disconnect'}]}))"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }
}

impl Client for ClickhouseClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        if v["type"] == "disconnect" {
            return Ok(ClientActionResult::Disconnect);
        }
        check(&v)?;
        Ok(ClientActionResult::Custom {
            name: v["type"].as_str().unwrap_or_default().to_string(),
            data: v,
        })
    }
}

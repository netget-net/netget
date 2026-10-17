//! Snowflake client: what the model is told and what it may do.

use std::sync::LazyLock;

use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};

use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::actions::{ActionDefinition, Parameter, ParameterDefinition, StartupExamples};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::state::app_state::AppState;

pub struct SnowflakeClientProtocol;

impl SnowflakeClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SnowflakeClientProtocol {
    fn default() -> Self {
        Self::new()
    }
}

fn p(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.to_string(),
        type_hint: type_hint.to_string(),
        description: description.to_string(),
        required,
    }
}

fn run_sql() -> ActionDefinition {
    ActionDefinition {
        name: "run_sql".to_string(),
        description: format!(
            "Run one SQL statement in the session (query-request). Any statement: SELECT, CREATE, INSERT, UPDATE, DELETE, USE, SHOW, ALTER SESSION. The answer is snowflake_query_result with the column types and the rows decoded from them, or snowflake_error. At most max_rows rows are delivered (default {}, at most {}); truncated says whether more existed.",
            super::DEFAULT_MAX_ROWS,
            super::MAX_ROWS_LIMIT
        ),
        parameters: vec![
            p("sql", "string", "One SQL statement, without a trailing semicolon", true),
            p("max_rows", "number", "How many rows to deliver at most", false),
        ],
        example: json!({"type": "run_sql", "sql": "SELECT id, body FROM notes ORDER BY id", "max_rows": 50}),
        log_template: Some(LogTemplate::new().with_info("-> Snowflake query-request {sql}")),
    }
}

fn logout() -> ActionDefinition {
    ActionDefinition {
        name: "logout".to_string(),
        description:
            "End the session on the server (POST /session?delete=true) and close the client."
                .to_string(),
        parameters: vec![],
        example: json!({"type": "logout"}),
        log_template: Some(LogTemplate::new().with_info("-> Snowflake logout")),
    }
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![run_sql(), logout()]
}

fn ev(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, run_sql().example.clone())
        .with_parameters(params)
        .with_actions(actions())
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "snowflake_connected",
        "The client logged in (login-request) and holds a session; nothing has run yet.",
        vec![
            p("endpoint", "string", "The server's base URL", true),
            p(
                "user",
                "string",
                "The login name the session was opened with",
                true,
            ),
            p(
                "account",
                "string",
                "The account name sent at login, if any",
                false,
            ),
            p(
                "database",
                "string",
                "The session's database as the server reported it",
                false,
            ),
            p(
                "schema",
                "string",
                "The session's schema as the server reported it",
                false,
            ),
            p(
                "warehouse",
                "string",
                "The session's warehouse as the server reported it",
                false,
            ),
            p(
                "role",
                "string",
                "The session's role as the server reported it",
                false,
            ),
            p(
                "server_version",
                "string",
                "The version the server reported",
                false,
            ),
            p("session_id", "string", "The server's session id", false),
        ],
    )
});

pub static QUERY_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "snowflake_query_result",
        "A statement run with run_sql succeeded.",
        vec![
            p("sql", "string", "The statement exactly as it was sent", true),
            p("query_id", "string", "The server's query id", true),
            p("columns", "array", "One {name, type, nullable, precision, scale} per column, in order", true),
            p("rows", "array", "One object per row keyed by column name (a repeated name gets _2, _3). FIXED with scale 0 is a number, with a scale an exact decimal string; REAL a number; BOOLEAN true/false; DATE 2026-10-14; TIME 12:34:56.123; TIMESTAMP_NTZ 2026-10-14T12:34:56.123 (no zone), TIMESTAMP_LTZ the instant in UTC ending Z, TIMESTAMP_TZ the wall time with its offset; VARIANT/OBJECT/ARRAY the JSON value; BINARY {binary_length}; NULL null", true),
            p("row_count", "number", "How many rows are in rows (at most max_rows)", true),
            p("total", "number", "The row count the server reported (for a statement, what it affected)", false),
            p("rows_affected", "number", "Rows inserted, updated or deleted, read from the server's 'number of rows ...' columns", false),
            p("truncated", "boolean", "True when more rows existed than were delivered", true),
            p("chunks_not_fetched", "number", "Result chunks the server put at other URLs; they are never fetched", true),
            p("result_format", "string", "json or arrow: how the server sent the rows", true),
            p("decode_warnings", "array", "Cells that did not read as their column's type, given as the server's text instead: {column, type, reason}", true),
            p("statement_type_id", "number", "The server's statement type id", false),
        ],
    )
});

pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "snowflake_error",
        "A statement failed: the server refused it (success false, with its code and message), or the response could not be read. The session is still open.",
        vec![
            p("operation", "string", "The action that failed: run_sql", true),
            p("sql", "string", "The statement that failed, exactly as it was sent", false),
            p("code", "string", "The server's error code, e.g. 002003 (object does not exist)", false),
            p("sql_state", "string", "The SQLSTATE, when the server gave one", false),
            p("message", "string", "What went wrong, in the server's words or this client's", true),
            p("query_id", "string", "The server's query id, when it gave one", false),
            p("http_status", "number", "The HTTP status of the response", false),
        ],
    )
});

/// Validate an action and return the internal request it becomes.
pub fn request(v: &Value) -> Result<(String, Value)> {
    let kind = v
        .get("type")
        .and_then(Value::as_str)
        .context("an action needs a type")?;
    match kind {
        "run_sql" => {
            let sql = v
                .get("sql")
                .and_then(Value::as_str)
                .context("run_sql needs sql")?
                .trim()
                .trim_end_matches(';')
                .trim();
            ensure!(!sql.is_empty(), "run_sql: sql is empty");
            ensure!(
                sql.len() <= super::MAX_SQL_BYTES,
                "run_sql: the statement is {} bytes; at most {} are sent",
                sql.len(),
                super::MAX_SQL_BYTES
            );
            let max_rows = match v.get("max_rows") {
                None | Some(Value::Null) => super::DEFAULT_MAX_ROWS as u64,
                Some(n) => n.as_u64().context("max_rows is a whole number")?,
            };
            ensure!(
                (1..=super::MAX_ROWS_LIMIT as u64).contains(&max_rows),
                "max_rows is 1..={}",
                super::MAX_ROWS_LIMIT
            );
            Ok((kind.to_string(), json!({"sql": sql, "max_rows": max_rows})))
        }
        "logout" => Ok((kind.to_string(), json!({}))),
        other => bail!("Unknown Snowflake client action: {other}"),
    }
}

fn param(
    name: &str,
    type_hint: &str,
    description: &str,
    required: bool,
    example: Value,
    default: Option<Value>,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required,
        example,
        default,
    }
}

impl Protocol for SnowflakeClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Snowflake"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Snowflake"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "snowflake client",
            "connect to snowflake",
            "snowflake warehouse",
            "fakesnow",
        ]
    }
    fn description(&self) -> &'static str {
        "Snowflake client: logs in over the connector REST protocol, runs SQL and reads typed rows (JSON or Arrow results)"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            QUERY_RESULT_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            param("username", "string", "The login name (LOGIN_NAME)", true, json!("analyst"), None),
            param("password", "string", "The password (username/password authenticator). Sent in the login body; use an https:// endpoint for a real account", true, json!("secret"), None),
            param("endpoint_url", "string", "The server's base URL, used exactly as given, e.g. http://127.0.0.1:8085. Without it the client's remote_addr is the target (host:port means http://host:port). There is no default: the client never derives an address from the account name", false, json!("http://127.0.0.1:8085"), None),
            param("account", "string", "The account name sent at login (ACCOUNT_NAME). It never decides where the client connects", false, json!("myorg-myaccount"), None),
            param("database", "string", "The database to open the session in (databaseName)", false, json!("ANALYTICS"), None),
            param("schema", "string", "The schema to open the session in (schemaName)", false, json!("PUBLIC"), None),
            param("warehouse", "string", "The warehouse for the session", false, json!("COMPUTE_WH"), None),
            param("role", "string", "The role for the session (roleName)", false, json!("ANALYST"), None),
            param("request_timeout_secs", "number", "Seconds a login or a statement may take, polling included (1..=3600)", false, json!(60), Some(json!(super::REQUEST_TIMEOUT.as_secs()))),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Snowflake connector REST protocol over HTTP(S) (reqwest natively, the hyper transport in the browser build): POST /session/v1/login-request with the username/password authenticator and databaseName/schemaName/warehouse/roleName in the query string; POST /queries/v1/query-request with requestId and Authorization: Snowflake Token=\"...\"; query-in-progress (333333/333334) polled at the same-origin getResultUrl; an expired session (390112) renewed once with POST /session/token-request and the master token; POST /session?delete=true to log out. Results are decoded from JSON rowsets or from Arrow IPC streams (rowsetBase64, read by a hand-written bounded reader) using rowtype's logical types; result chunks at presigned URLs are counted and never fetched")
            .llm_control("Which SQL to run, how many rows to read and when to log out; it reads typed rows, column descriptions, row counts and the server's error codes")
            .e2e_testing("tests/client/snowflake/real_server_test.rs drives two independent servers with the model mocked: fakesnow 0.11.22 (Python, DuckDB underneath, Arrow results) and nnnkkk7/snowflake-emulator v0.0.9 (Go, DuckDB underneath, JSON results). Against fakesnow the model creates a table of nine types, inserts, reads the rows back typed, inserts a row built from the decoded values, reads a server error and logs out; snowflake-connector-python reads the table back over a second session. Against the emulator the same create/insert/select/derived-insert chain is read back over a separate REST session; each server's access log shows the logout. The follow-up bound and an LLM failure are tested against fakesnow, a refused login against the emulator; session_test.rs covers token renewal and query polling against a scripted server. Fails rather than skips without either server")
            .notes("Experimental against the client Beta bar: both servers are independent re-implementations of Snowflake's connector protocol, not Snowflake, and each reproduces a subset of it (fakesnow answers every SELECT in Arrow, the emulator writes NULL as an empty string and DATE/TIME as Go time strings, which this client reports as decode_warnings rather than guessing). No real Snowflake account was used, so TLS, real Arrow chunking, MFA, key-pair, OAuth and SSO authenticators, async query polling and token renewal against real Snowflake are untested; polling and renewal are exercised only against a scripted server in the tests. Bound parameters, PUT/GET stage transfers and multi-statement requests are not implemented")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the Snowflake endpoint http://127.0.0.1:8085 as analyst, create a notes table and read it back"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({
            "type": "open_client",
            "protocol": "Snowflake",
            "remote_addr": "127.0.0.1:8085",
            "startup_params": {"username": "analyst", "password": "secret", "database": "ANALYTICS", "schema": "PUBLIC"},
            "instruction": "List the tables, then count the rows of each"
        });
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "snowflake_connected", "handler": {"type": "static", "actions": [
                {"type": "run_sql", "sql": "SHOW TABLES"}
            ]}},
            {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1] = json!({"event_pattern": "snowflake_query_result", "handler": {
            "type": "script", "language": "python",
            "code": "import json,sys\ne=json.load(sys.stdin)['event']\na=[{'type':'run_sql','sql':'SELECT COUNT(*) AS N FROM '+r['name']} for r in e.get('rows',[]) if 'name' in r][:5]\nprint(json.dumps({'actions':a}))"
        }});
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }
}

impl Client for SnowflakeClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        let (name, data) = request(&v)?;
        Ok(ClientActionResult::Custom { name, data })
    }
}

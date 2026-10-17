//! Db2 (DRDA) client: what the model is told and what it may do.

use std::sync::LazyLock;

use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};

use crate::llm::actions::client_trait::{Client, ClientActionResult};
use crate::llm::actions::protocol_trait::Protocol;
use crate::llm::actions::{ActionDefinition, Parameter, ParameterDefinition, StartupExamples};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::state::app_state::AppState;

use super::wire;

pub struct Db2ClientProtocol;

impl Db2ClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Db2ClientProtocol {
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

fn execute_statement() -> ActionDefinition {
    ActionDefinition {
        name: "execute_statement".to_string(),
        description: "Run one SQL statement that returns no rows (CREATE, INSERT, UPDATE, DELETE, DROP, ...) with EXCSQLIMM. The answer is db2_statement_result (SQLCODE, SQLSTATE, rows affected) or db2_error. Changes are not durable until commit unless the client was opened with autocommit.".to_string(),
        parameters: vec![p("sql", "string", "The SQL statement, without a trailing semicolon", true)],
        example: json!({"type": "execute_statement", "sql": "INSERT INTO notes (id, body) VALUES (1, 'hello')"}),
        log_template: Some(LogTemplate::new().with_info("-> Db2 EXCSQLIMM {sql}")),
    }
}

fn execute_query() -> ActionDefinition {
    ActionDefinition {
        name: "execute_query".to_string(),
        description: format!("Run one SELECT (or VALUES) statement: prepare it, open a cursor and fetch rows. The answer is db2_query_result with the column descriptions and the rows as objects keyed by column name, or db2_error. At most max_rows rows are delivered (default {}, at most {}); truncated says whether more existed.", wire::DEFAULT_MAX_ROWS, wire::MAX_ROWS_LIMIT),
        parameters: vec![
            p("sql", "string", "The query, without a trailing semicolon", true),
            p("max_rows", "number", "How many rows to deliver at most", false),
        ],
        example: json!({"type": "execute_query", "sql": "SELECT id, body FROM notes ORDER BY id", "max_rows": 50}),
        log_template: Some(LogTemplate::new().with_info("-> Db2 PRPSQLSTT/OPNQRY {sql}")),
    }
}

fn commit() -> ActionDefinition {
    ActionDefinition {
        name: "commit".to_string(),
        description: "Commit the unit of work (RDBCMM). The answer is db2_transaction_result."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "commit"}),
        log_template: Some(LogTemplate::new().with_info("-> Db2 RDBCMM")),
    }
}

fn rollback() -> ActionDefinition {
    ActionDefinition {
        name: "rollback".to_string(),
        description: "Roll back the unit of work (RDBRLLBCK), undoing every change since the last commit. The answer is db2_transaction_result.".to_string(),
        parameters: vec![],
        example: json!({"type": "rollback"}),
        log_template: Some(LogTemplate::new().with_info("-> Db2 RDBRLLBCK")),
    }
}

fn disconnect() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".to_string(),
        description: "Close the connection. Uncommitted work is rolled back by the server."
            .to_string(),
        parameters: vec![],
        example: json!({"type": "disconnect"}),
        log_template: Some(LogTemplate::new().with_info("-> Db2 disconnect")),
    }
}

pub fn actions() -> Vec<ActionDefinition> {
    vec![
        execute_statement(),
        execute_query(),
        commit(),
        rollback(),
        disconnect(),
    ]
}

fn ev(id: &str, description: &str, params: Vec<Parameter>) -> EventType {
    EventType::new(id, description, execute_query().example.clone())
        .with_parameters(params)
        .with_actions(actions())
}

pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "db2_connected",
        "The client logged in (EXCSAT, ACCSEC, SECCHK) and opened the database (ACCRDB); nothing has run yet.",
        vec![
            p("remote_addr", "string", "The server's address", true),
            p("database", "string", "The relational database name opened", true),
            p("user", "string", "The user id that logged in", true),
            p("server_class", "string", "The server's class name (SRVCLSNM), e.g. QDB2/LINUXX8664 or Apache Derby", true),
            p("server_release", "string", "The server's product release level (SRVRLSLV)", true),
            p("server_product_id", "string", "The product id the server gave when the database opened (PRDID)", true),
            p("data_representation", "string", "The server's TYPDEFNAM (byte order and character set family)", true),
        ],
    )
});

pub static STATEMENT_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "db2_statement_result",
        "A statement run with execute_statement succeeded (SQLCODE 0, or a positive warning).",
        vec![
            p(
                "sql",
                "string",
                "The statement text exactly as it was sent with EXCSQLIMM",
                true,
            ),
            p(
                "sqlcode",
                "number",
                "0, or a positive warning code (100: no row matched)",
                true,
            ),
            p(
                "sqlstate",
                "string",
                "The SQLSTATE, blank on plain success",
                true,
            ),
            p(
                "row_count",
                "number",
                "Rows inserted, updated or deleted (SQLERRD3)",
                true,
            ),
            p(
                "message_tokens",
                "array",
                "Message tokens the server attached",
                true,
            ),
            p(
                "committed",
                "boolean",
                "True when autocommit committed it",
                true,
            ),
        ],
    )
});

pub static QUERY_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "db2_query_result",
        "A query run with execute_query returned its rows.",
        vec![
            p("sql", "string", "The query text exactly as it was prepared and opened", true),
            p("columns", "array", "One {name, type, nullable} per column, in order", true),
            p("rows", "array", "One object per row keyed by column name. Integers and floats are numbers; DECIMAL is an exact string; DATE, TIME and TIMESTAMP are the server's strings; NULL is null; binary columns are {binary_length}", true),
            p("row_count", "number", "How many rows are in rows (at most max_rows)", true),
            p("truncated", "boolean", "True when more rows existed than max_rows", true),
            p("warnings", "array", "Warning SQLCAs attached to rows", true),
        ],
    )
});

pub static TRANSACTION_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "db2_transaction_result",
        "A commit or rollback finished.",
        vec![
            p("operation", "string", "commit or rollback", true),
            p(
                "outcome",
                "string",
                "committed or rolled_back, as the server reported the unit of work",
                true,
            ),
            p(
                "statements",
                "array",
                "The statements this client ran in that unit of work (the last 16)",
                true,
            ),
            p(
                "sqlcode",
                "number",
                "The SQLCODE the server returned with the commit or rollback (0 on success)",
                true,
            ),
        ],
    )
});

pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    ev(
        "db2_error",
        "An action failed: the server refused the SQL (negative SQLCODE), answered with a DRDA error reply, or returned something this client cannot decode. The connection is still open.",
        vec![
            p("operation", "string", "execute_statement, prepare, open_query, fetch, commit or rollback", true),
            p("sql", "string", "The statement, where there was one", false),
            p("sqlcode", "number", "The negative SQLCODE, for an SQL error", false),
            p("sqlstate", "string", "The SQLSTATE, for an SQL error", false),
            p("message_tokens", "array", "The server's message tokens (Db2 sends tokens, not message text)", false),
            p("reply_message", "string", "The DRDA reply message, for a protocol-level refusal", false),
            p("message", "string", "What went wrong, in words", true),
            p("rolled_back", "boolean", "True when the server ended the unit of work abnormally (deadlock, timeout)", false),
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
        "execute_statement" | "execute_query" => {
            let sql = v
                .get("sql")
                .and_then(Value::as_str)
                .with_context(|| format!("{kind} needs sql"))?
                .trim()
                .trim_end_matches(';')
                .trim();
            ensure!(!sql.is_empty(), "{kind}: sql is empty");
            ensure!(
                sql.len() <= wire::MAX_SQL_BYTES,
                "{kind}: the statement is {} bytes; at most {} are sent",
                sql.len(),
                wire::MAX_SQL_BYTES
            );
            let mut data = json!({ "sql": sql });
            if kind == "execute_query" {
                let max_rows = match v.get("max_rows") {
                    None | Some(Value::Null) => wire::DEFAULT_MAX_ROWS as u64,
                    Some(n) => n.as_u64().context("max_rows is a whole number")?,
                };
                ensure!(
                    (1..=wire::MAX_ROWS_LIMIT as u64).contains(&max_rows),
                    "max_rows is 1..={}",
                    wire::MAX_ROWS_LIMIT
                );
                data["max_rows"] = json!(max_rows);
            }
            Ok((kind.to_string(), data))
        }
        "commit" | "rollback" => Ok((kind.to_string(), json!({}))),
        other => bail!("Unknown Db2 client action: {other}"),
    }
}

impl Protocol for Db2ClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "Db2"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>DRDA>Db2"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "db2 client",
            "drda client",
            "connect to db2",
            "ibm db2",
            "apache derby",
            "derby network server",
        ]
    }
    fn description(&self) -> &'static str {
        "Db2 client: speaks DRDA to IBM Db2 or Apache Derby, logs in, runs statements and queries, and commits or rolls back"
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
            STATEMENT_RESULT_EVENT.clone(),
            QUERY_RESULT_EVENT.clone(),
            TRANSACTION_RESULT_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            ParameterDefinition {
                name: "database".into(),
                type_hint: "string".into(),
                description: "The relational database name (RDBNAM). Apache Derby reads connection attributes after it, e.g. sample;create=true".into(),
                required: true,
                example: json!("SAMPLE"),
                default: None,
            },
            ParameterDefinition {
                name: "username".into(),
                type_hint: "string".into(),
                description: "The user id sent in SECCHK (printable ASCII)".into(),
                required: true,
                example: json!("db2inst1"),
                default: None,
            },
            ParameterDefinition {
                name: "password".into(),
                type_hint: "string".into(),
                description: "The password, sent in the clear (security mechanism USRIDPWD). Without one the client logs in with the user id alone (USRIDONL)".into(),
                required: false,
                example: json!("secret"),
                default: None,
            },
            ParameterDefinition {
                name: "autocommit".into(),
                type_hint: "boolean".into(),
                description: "Commit after every successful statement and query".into(),
                required: false,
                example: json!(true),
                default: Some(json!(super::DEFAULT_AUTOCOMMIT)),
            },
            ParameterDefinition {
                name: "product_id".into(),
                type_hint: "string".into(),
                description: "The 8-character product id (PRDID, pppvvrrm) sent in ACCRDB and EXCSAT. Apache Derby admits only its own client's prefix, DNC; IBM Db2 accepts any".into(),
                required: false,
                example: json!("DNC10170"),
                default: Some(json!(super::DEFAULT_PRODUCT_ID)),
            },
            ParameterDefinition {
                name: "reply_timeout_secs".into(),
                type_hint: "number".into(),
                description: "Seconds to wait for a whole reply before the connection is given up (1..=3600). Statements waiting on a lock legitimately take a while".into(),
                required: false,
                example: json!(60),
                default: Some(json!(super::REPLY_TIMEOUT.as_secs())),
            },
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .privilege_requirement(PrivilegeRequirement::None)
            .implementation("Hand-rolled DRDA requester (src/client/db2/wire.rs) at SQLAM 7: EXCSAT, ACCSEC, SECCHK (USRIDPWD or USRIDONL), ACCRDB declaring QTDSQLASC with UTF-8 TYPDEFOVR; EXCSQLIMM for statements; PRPSQLSTT (extended SQLDA) then OPNQRY/CNTQRY/CLSQRY for queries, with the QRYDSC row layout and QRYDTA rows decoded (integers, DECIMAL, floats, character, graphic, DATE/TIME/TIMESTAMP, BOOLEAN, NULL) honouring the server's byte order and CCSIDs; RDBCMM and RDBRLLBCK. DSS continuation, extended object lengths and rows split across query blocks are handled; every length is bounded")
            .llm_control("Which statements and queries to run, how many rows to fetch, and when to commit or roll back; it reads SQLCODE, SQLSTATE, row counts, column descriptions and decoded rows")
            .e2e_testing("tests/client/db2/real_server_test.rs drives Apache Derby 10.17.1.0's network server (a Java DRDA implementation sharing no code with NetGet) with the model mocked: create a table of ten types, insert, commit, select the rows back typed, insert a row built from them, commit, insert and roll back, and a bad statement's error SQLCA. Derby's own ij client reads the table back, a recording proxy feeds both directions to tshark's drda dissector, Derby's statement log shows what ran, and a refused login, the follow-up bound and an LLM failure are tested against it too. Fails rather than skips without java or the Derby jars")
            .notes("Experimental: one independent server (Derby), not the two the client Beta bar asks for. IBM Db2 itself is not tested: its Community image is linux/amd64 only and needs a privileged container. No LOBs, XML, DECFLOAT, user-defined types or parameter markers; no encrypted security mechanisms (passwords go in the clear, as USRIDPWD sends them); DDM strings are EBCDIC CCSID 37 (UNICODEMGR is not negotiated); S/390 hexadecimal floats are refused. The product id defaults to DNC10170 because Derby refuses any other prefix")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to the Db2 database SAMPLE at db2.example.com:50000 as db2inst1 and list the ten most recent orders"
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let llm = json!({
            "type": "open_client",
            "protocol": "Db2",
            "remote_addr": "127.0.0.1:50000",
            "startup_params": {"database": "SAMPLE", "username": "db2inst1", "password": "secret"},
            "instruction": "List the tables in schema DB2INST1, then count the rows of each"
        });
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([
            {"event_pattern": "db2_connected", "handler": {"type": "static", "actions": [
                {"type": "execute_query", "sql": "SELECT TABNAME FROM SYSCAT.TABLES WHERE TABSCHEMA = 'DB2INST1'"}
            ]}},
            {"event_pattern": "*", "handler": {"type": "static", "actions": []}}
        ]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][1] = json!({"event_pattern": "db2_query_result", "handler": {
            "type": "script", "language": "python",
            "code": "import json,sys\ne=json.load(sys.stdin)['event']\na=[{'type':'execute_query','sql':'SELECT COUNT(*) AS N FROM DB2INST1.'+r['TABNAME']} for r in e.get('rows',[]) if 'TABNAME' in r][:5]\nprint(json.dumps({'actions':a}))"
        }});
        StartupExamples::new(llm, scripted, static_example)
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }
}

impl Client for Db2ClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        if v.get("type").and_then(Value::as_str) == Some("disconnect") {
            return Ok(ClientActionResult::Disconnect);
        }
        let (name, data) = request(&v)?;
        Ok(ClientActionResult::Custom { name, data })
    }
}

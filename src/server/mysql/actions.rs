//! MySQL protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::server::connection::ConnectionId;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::{Arc, LazyLock};
use tokio::sync::mpsc;
use tracing::debug;

/// MySQL protocol action handler
pub struct MysqlProtocol {
    _connection_id: ConnectionId,
    _app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
}

impl MysqlProtocol {
    pub fn new(
        connection_id: ConnectionId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Self {
        Self {
            _connection_id: connection_id,
            _app_state: app_state,
            status_tx,
        }
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for MysqlProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
                crate::llm::actions::ParameterDefinition {
                    name: "send_first".to_string(),
                    type_hint: "boolean".to_string(),
                    description: "Unsupported by this server and refused if set to true. MySQL: the server already sends its initial handshake packet unconditionally, because the protocol requires it - there is nothing for this flag to turn on."
                        .to_string(),
                    required: false,
                    example: serde_json::json!(false),
                    default: None,
                },
            ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // No user-triggered actions. (A `list_mysql_connections` action used to be declared
        // here; its executor returned a hardcoded empty list, so it only ever misled the model.)
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            mysql_query_response_action(),
            mysql_error_response_action(),
            mysql_ok_response_action(),
            close_this_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "MySQL"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_mysql_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>MySQL"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["mysql"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            // Beta: exercised against two independent clients — mysql_async and the real
            // `mysql` CLI — covering handshake, queries, errors and prepared statements.
            // Not Stable: the Stable bar additionally wants a green pcap oracle, a fuzz
            // target with a depth-bomb corpus, and a test per declared bound, none of which
            // exist here.
            .state(DevelopmentState::Beta)
            .well_known_port(3306)
            .implementation("opensrv-mysql v0.7 protocol library")
            // The number this server publishes and the number it enforces are one number:
            // opensrv-mysql answers `SELECT @@max_allowed_packet` with 67108864 itself,
            // without consulting this shim, and until `packet_limit` existed nothing was
            // ever compared against it.
            .max_inbound_bytes(crate::server::mysql::packet_limit::MAX_PACKET_BYTES)
            .llm_control("Query responses (result sets, OK packets, ERR packets)")
            .e2e_testing(
                "Two independent clients, neither skipped nor #[ignore]d. (1) the mysql_async \
                 crate, text and binary (prepared) protocols \
                 (tests/server/mysql/test.rs, prepared_statement_test.rs). (2) the real \
                 `mysql` CLI, 9.3.0 (tests/server/mysql/real_client_test.rs): connect, a \
                 SELECT whose rows the model authors, and a statement answered with an ERR \
                 packet, asserted on what the client printed — including the \
                 caching_sha2_password fast-auth branch a client that was given a password \
                 takes. That test fails rather than skips when the binary is absent. Until \
                 September 2026 the CLI could not connect at all ('Authentication plugin \
                 mysql_native_password cannot be loaded'), so the rating rested on \
                 mysql_async alone being more permissive than the client a user would reach \
                 for.",
            )
            .notes(
                "THIS SERVER AUTHENTICATES NOTHING. It offers caching_sha2_password so a \
                 current client can complete the connection phase, and then accepts whatever \
                 that client sent: no password is stored or compared, the model is not asked, \
                 the nonce is a fixed string, and mysql_native_password is still accepted \
                 too. 'Offers caching_sha2_password' is a statement about the packets, not \
                 about security. No TLS either. Prepared statements work and report their `?` \
                 count, but parameter values are not substituted - the model sees the `?`.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "MySQL database server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a MySQL server on port 3306"
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic answers for a couple of well-known queries, falling back
        // to an empty OK for writes. Real column/row shapes, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "mysql_query":
    q = event.get("query", "").strip().rstrip(";").upper()
    if q.startswith("SELECT VERSION()"):
        actions = [{"type": "mysql_query_response",
                    "columns": [{"name": "version", "type": "VARCHAR"}],
                    "rows": [["8.0.36"]]}]
    elif q.startswith("SELECT"):
        actions = [{"type": "mysql_query_response",
                    "columns": [{"name": "id", "type": "INT"},
                                {"name": "name", "type": "VARCHAR"}],
                    "rows": [[1, "alice"], [2, "bob"]]}]
    else:
        actions = [{"type": "mysql_ok_response", "affected_rows": 0}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: reason about the SQL to synthesise coherent rows.
            json!({
                "type": "open_server",
                "port": 3306,
                "base_stack": "mysql",
                "instruction": "Act as a MySQL server for a 'products' database. Answer SELECT queries by generating plausible rows that satisfy the WHERE clause and requested columns; treat INSERT/UPDATE/DELETE as succeeding and report affected_rows. Keep results consistent across queries in the same session."
            }),
            // Script mode: fixed answers for known queries, no LLM call.
            json!({
                "type": "open_server",
                "port": 3306,
                "base_stack": "mysql",
                "event_handlers": [{
                    "event_pattern": "mysql_query",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode: Fixed responses
            json!({
                "type": "open_server",
                "port": 3306,
                "base_stack": "mysql",
                "event_handlers": [{
                    "event_pattern": "mysql_query",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "mysql_query_response",
                            "columns": [{"name": "result", "type": "VARCHAR"}],
                            "rows": [["OK"]]
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for MysqlProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::mysql::MysqlServer;
            // `send_first` stays declared so a caller that passes `false` still validates - an
            // undeclared key is refused outright - but `true` is refused rather than ignored.
            // It was read here, threaded through spawn, and dropped at the far end as
            // `_send_first`: a knob advertised to the model, plumbed through three hops, and
            // silently doing nothing. MySQL: the server already sends its initial handshake packet unconditionally, because the protocol requires it - there is nothing for this flag to turn on.
            let send_first = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_bool("send_first"))
                .transpose()?
                .flatten()
                .unwrap_or(false);
            if send_first {
                return Err(anyhow::anyhow!(
                    "send_first is not supported by the MySQL server: the server already sends its initial handshake packet unconditionally, because the protocol requires it - there is nothing for this flag to turn on"
                ));
            }

            MysqlServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                send_first,
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
            "mysql_query_response" => self.execute_mysql_query_response(action),
            "mysql_error_response" => self.execute_mysql_error_response(action),
            "mysql_ok_response" => self.execute_mysql_ok_response(action),
            "close_this_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown MySQL action: {}", action_type)),
        }
    }
}

impl MysqlProtocol {
    fn execute_mysql_query_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Extract columns and rows from the action
        let columns = action
            .get("columns")
            .and_then(|v| v.as_array())
            .context("Missing 'columns' array")?;

        let rows = action
            .get("rows")
            .and_then(|v| v.as_array())
            .context("Missing 'rows' array")?;

        debug!(
            "MySQL query response: {} columns, {} rows",
            columns.len(),
            rows.len()
        );

        let _ = self.status_tx.send(format!(
            "[DEBUG] MySQL → Result set: {} columns, {} rows",
            columns.len(),
            rows.len()
        ));

        // Return a custom action result with the query response data
        Ok(ActionResult::Custom {
            name: "mysql_query_response".to_string(),
            data: json!({
                "columns": columns,
                "rows": rows
            }),
        })
    }

    fn execute_mysql_error_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Truncating with `as u16` turned an out-of-range code into an unrelated one; keep the
        // documented default instead.
        let error_code = action
            .get("error_code")
            .and_then(|v| v.as_u64())
            .and_then(|c| u16::try_from(c).ok())
            .unwrap_or(1064);

        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");

        debug!("MySQL error response: {} - {}", error_code, message);

        let _ = self
            .status_tx
            .send(format!("[DEBUG] MySQL ✗ Error {}: {}", error_code, message));

        Ok(ActionResult::Custom {
            name: "mysql_error".to_string(),
            data: json!({
                "error_code": error_code,
                "message": message
            }),
        })
    }

    fn execute_mysql_ok_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let affected_rows = action
            .get("affected_rows")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let last_insert_id = action
            .get("last_insert_id")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        debug!(
            "MySQL OK response: affected_rows={}, last_insert_id={}",
            affected_rows, last_insert_id
        );

        let _ = self.status_tx.send(format!(
            "[DEBUG] MySQL → OK: {} rows affected",
            affected_rows
        ));

        Ok(ActionResult::Custom {
            name: "mysql_ok".to_string(),
            data: json!({
                "affected_rows": affected_rows,
                "last_insert_id": last_insert_id
            }),
        })
    }
}

/// Action definition: Send MySQL query response
pub fn mysql_query_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "mysql_query_response".to_string(),
        description: "The answer to any statement that returns rows - SELECT (including \
                      SELECT 1, SELECT VERSION(), SELECT @@version_comment), SHOW, DESCRIBE. A \
                      single value is one column and one row, and each row is an ARRAY of \
                      values in column order, e.g. \"rows\": [[\"8.0.36\"]]. Never answer a \
                      SELECT with mysql_ok_response: an OK packet carries no rows, so the client \
                      prints nothing. One response per query."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "columns".to_string(),
                type_hint: "array".to_string(),
                description: "Array of column definitions. Each column needs 'name' and 'type'. \
                              Recognised types: INT, INTEGER, BIGINT, SMALLINT, TINYINT, FLOAT, DOUBLE, \
                              DECIMAL, DATE, TIME, DATETIME, TIMESTAMP, BLOB, BINARY, TEXT, VARCHAR \
                              (anything else is treated as VARCHAR). The type sets the column metadata \
                              and how each value is encoded: send a number for the numeric types, \
                              'YYYY-MM-DD' for DATE, 'HH:MM:SS' for TIME, 'YYYY-MM-DD HH:MM:SS' for \
                              DATETIME/TIMESTAMP. A value that does not fit its column's type is sent \
                              as NULL".to_string(),
                required: true,
            },
            Parameter {
                name: "rows".to_string(),
                type_hint: "array".to_string(),
                description: "Array of rows. Each row is an array of values matching the column \
                              order. JSON null is a SQL NULL. Rows shorter than the column list \
                              are padded with NULLs; extra values are dropped".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "mysql_query_response",
            "columns": [{"name": "id", "type": "INT"}, {"name": "name", "type": "VARCHAR"}],
            "rows": [[1, "Alice"], [2, "Bob"]]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> MySQL {columns_len} cols, {rows_len} rows")
                .with_debug("MySQL mysql_query_response: {columns_len} columns, {rows_len} rows"),
        ),
    }
}

/// Action definition: Send MySQL error response
pub fn mysql_error_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "mysql_error_response".to_string(),
        description: "Send an error response to the client".to_string(),
        parameters: vec![
            Parameter {
                name: "error_code".to_string(),
                type_hint: "number".to_string(),
                description:
                    "MySQL error number. Sent verbatim when it is one of the recognised codes: \
                     1044, 1045, 1046, 1049, 1050, 1051, 1052, 1054, 1062, 1064, 1065, 1136, \
                     1146, 1149, 1216, 1217, 1364, 1451, 1452, 1690. Any other value is reported \
                     to the client as 1105 (unknown error) with your message unchanged"
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Error message to display to the client".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "mysql_error_response",
            "error_code": 1146,
            "message": "Table 'database.table_name' doesn't exist"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> MySQL ERR {error_code}: {message}")
                .with_debug("MySQL mysql_error_response: code={error_code}, message={message}"),
        ),
    }
}

/// Action definition: Send MySQL OK response
pub fn mysql_ok_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "mysql_ok_response".to_string(),
        description: "OK packet for a statement that returns no rows: INSERT, UPDATE, \
                      DELETE, CREATE, SET, USE. Never for SELECT, SHOW or DESCRIBE - those are \
                      answered with mysql_query_response."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "affected_rows".to_string(),
                type_hint: "number".to_string(),
                description: "Number of rows affected by the query".to_string(),
                required: false,
            },
            Parameter {
                name: "last_insert_id".to_string(),
                type_hint: "number".to_string(),
                description: "Last insert ID for INSERT queries with auto_increment".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "mysql_ok_response",
            "affected_rows": 1,
            "last_insert_id": 42
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> MySQL OK, {affected_rows} rows affected")
                .with_debug("MySQL mysql_ok_response: affected_rows={affected_rows}, last_insert_id={last_insert_id}"),
        ),
    }
}

/// Action definition: Close current MySQL connection
pub fn close_this_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_this_connection".to_string(),
        description: "Close the current MySQL connection".to_string(),
        parameters: vec![],
        example: json!({"type": "close_this_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("MySQL connection closed")
                .with_debug("MySQL close_this_connection"),
        ),
    }
}

// ============================================================================
// MySQL Action Constants
//
// The same four definitions the `Protocol` impl advertises, as statics the event type can
// clone. They delegate to the functions above rather than repeating them: the two copies were
// byte-identical duplicates of ~120 lines, and a description edited in one and not the other
// would have shown the model one text and the executor another.
// ============================================================================

/// MySQL query response action constant
pub static MYSQL_QUERY_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(mysql_query_response_action);

/// MySQL error response action constant
pub static MYSQL_ERROR_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(mysql_error_response_action);

/// MySQL OK response action constant
pub static MYSQL_OK_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(mysql_ok_response_action);

/// MySQL close connection action constant
pub static MYSQL_CLOSE_CONNECTION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(close_this_connection_action);

// ============================================================================
// MySQL Event Type Constants
// ============================================================================

/// MySQL query event - triggered when client sends a query
pub static MYSQL_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mysql_query",
        "MySQL query received from client",
        json!({"type": "placeholder", "event_id": "mysql_query"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "query".to_string(),
            type_hint: "string".to_string(),
            description: "The SQL query string sent by the client".to_string(),
            required: true,
        },
        Parameter {
            name: "answer_with".to_string(),
            type_hint: "string".to_string(),
            description: "Which response shape the statement needs, from its first keyword. \
                          Absent when the server cannot tell."
                .to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        MYSQL_QUERY_RESPONSE_ACTION.clone(),
        MYSQL_ERROR_RESPONSE_ACTION.clone(),
        MYSQL_OK_RESPONSE_ACTION.clone(),
        MYSQL_CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("MySQL: {preview(query,80)}")
            .with_debug("MySQL query: {query}")
            .with_trace("MySQL: {json_pretty(.)}"),
    )
});

/// The `answer_with` event field for `sql`, or `None` when its first keyword does not say.
///
/// See `crate::utils::sql`. Told to "report the server version as 8.0.36-netget-eval", the model
/// answered the client's own `SELECT @@version_comment` and `SELECT VERSION()` with OK packets or
/// with rows written as objects, and the client printed nothing.
pub fn answer_with_for_query(sql: &str) -> Option<&'static str> {
    use crate::utils::sql::{statement_shape, StatementShape};
    match statement_shape(sql) {
        StatementShape::Rows => Some(
            "mysql_query_response: this statement returns rows - columns, and rows as arrays of \
             values (one column and one row for a single value) - never an OK packet",
        ),
        StatementShape::NoRows => Some(
            "mysql_ok_response: this statement returns no rows - affected_rows and, for an \
             INSERT, last_insert_id",
        ),
        StatementShape::Unknown => None,
    }
}

/// Get MySQL event types
pub fn get_mysql_event_types() -> Vec<EventType> {
    vec![MYSQL_QUERY_EVENT.clone()]
}

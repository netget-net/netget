//! PostgreSQL protocol actions implementation

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

/// PostgreSQL protocol action handler
pub struct PostgresqlProtocol {
    #[allow(dead_code)]
    connection_id: ConnectionId,
    #[allow(dead_code)]
    app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
}

impl PostgresqlProtocol {
    pub fn new(
        connection_id: ConnectionId,
        app_state: Arc<AppState>,
        status_tx: mpsc::UnboundedSender<String>,
    ) -> Self {
        Self {
            connection_id,
            app_state,
            status_tx,
        }
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for PostgresqlProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
                crate::llm::actions::ParameterDefinition {
                    name: "send_first".to_string(),
                    type_hint: "boolean".to_string(),
                    description: "Unsupported by this server and refused if set to true. PostgreSQL: the frontend sends the StartupMessage first, and a byte before it is a protocol violation the client cannot parse."
                        .to_string(),
                    required: false,
                    example: json!(false),
                    default: None,
                },
            ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // No user-triggered actions. (A `list_postgresql_connections` action used to be declared
        // here; its executor returned a hardcoded empty list, so it only ever misled the model.)
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            postgresql_query_response_action(),
            postgresql_error_response_action(),
            postgresql_ok_response_action(),
            close_this_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "PostgreSQL"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_postgresql_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>PostgreSQL"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["postgres", "psql"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            // Beta: exercised against two independent clients that share no code with each
            // other or with pgwire — tokio-postgres (Rust) and psql/libpq (C). Not Stable:
            // Stable additionally wants spec compliance and scripting support reviewed, which
            // has not been done here.
            .state(DevelopmentState::Beta)
            .well_known_port(5432)
            .implementation("pgwire v0.35 protocol library")
            .llm_control("Query responses (columns, rows, types)")
            .e2e_testing(
                "Two independent clients. tokio-postgres (tests/server/postgresql/test.rs, \
                 extended_query_test.rs, llm_failure_test.rs): simple query, and \
                 Parse/Bind/Describe/Execute with binary result columns decoded into real Rust \
                 types. psql 14 / libpq (real_client_test.rs, hard-fails when the binary is \
                 absent): the sslmode=prefer SSLRequest negotiation tokio-postgres+NoTls never \
                 sends, the startup handshake, a four-column three-row SELECT asserted on the \
                 exact text psql rendered (t/f booleans, a real NULL distinguished from an \
                 empty string), a CommandComplete tag, and an ErrorResponse whose SQLSTATE psql \
                 prints under VERBOSITY verbose. \
                 NOT proven: psql 14 sends every statement as a simple Query (no \\bind), so the \
                 extended protocol and binary formats rest on tokio-postgres alone; no client \
                 here exercises authentication or TLS (neither is implemented), bound parameter \
                 values, COPY, LISTEN/NOTIFY, cursors, or multi-statement simple queries.",
            )
            .notes(
                "No authentication, no TLS; simple and extended query protocols, text format only",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "PostgreSQL database server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a PostgreSQL server on port 5432"
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic answers for a version probe and generic SELECTs, with an
        // empty command-complete tag for writes. Real column/row shapes.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "postgresql_query":
    q = event.get("query", "").strip().rstrip(";").upper()
    if q.startswith("SELECT VERSION()"):
        actions = [{"type": "postgresql_query_response",
                    "columns": [{"name": "version", "type": "text"}],
                    "rows": [["PostgreSQL 16.2"]]}]
    elif q.startswith("SELECT"):
        actions = [{"type": "postgresql_query_response",
                    "columns": [{"name": "id", "type": "int4"},
                                {"name": "name", "type": "text"}],
                    "rows": [[1, "alice"], [2, "bob"]]}]
    else:
        actions = [{"type": "postgresql_ok_response", "tag": "OK"}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: reason about the SQL to synthesise coherent rows.
            json!({
                "type": "open_server",
                "port": 5432,
                "base_stack": "postgresql",
                "instruction": "Act as a PostgreSQL server for a 'users' database. Answer SELECT queries by generating plausible rows that satisfy the WHERE clause and requested columns; treat INSERT/UPDATE/DELETE as succeeding with a suitable command tag. Keep results consistent across queries in the same session."
            }),
            // Script mode: fixed answers for known queries, no LLM call.
            json!({
                "type": "open_server",
                "port": 5432,
                "base_stack": "postgresql",
                "event_handlers": [{
                    "event_pattern": "postgresql_query",
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
                "port": 5432,
                "base_stack": "postgresql",
                "event_handlers": [{
                    "event_pattern": "postgresql_query",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "postgresql_query_response",
                            "columns": [{"name": "result", "type": "text"}],
                            "rows": [["OK"]]
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for PostgresqlProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::postgresql::PostgresqlServer;
            // `send_first` stays declared so a caller that passes `false` still validates - an
            // undeclared key is refused outright - but `true` is refused rather than ignored.
            // It was read here, threaded through spawn, and dropped at the far end as
            // `_send_first`: a knob advertised to the model, plumbed through three hops, and
            // silently doing nothing. PostgreSQL: the frontend sends the StartupMessage first, and a byte before it is a protocol violation the client cannot parse.
            let send_first = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_bool("send_first"))
                .transpose()?
                .flatten()
                .unwrap_or(false);
            if send_first {
                return Err(anyhow::anyhow!(
                    "send_first is not supported by the PostgreSQL server: the frontend sends the StartupMessage first, and a byte before it is a protocol violation the client cannot parse"
                ));
            }

            PostgresqlServer::spawn_with_llm_actions(
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
            "postgresql_query_response" => self.execute_postgresql_query_response(action),
            "postgresql_error_response" => self.execute_postgresql_error_response(action),
            "postgresql_ok_response" => self.execute_postgresql_ok_response(action),
            "close_this_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!(
                "Unknown PostgreSQL action: {}",
                action_type
            )),
        }
    }
}

impl PostgresqlProtocol {
    fn execute_postgresql_query_response(&self, action: serde_json::Value) -> Result<ActionResult> {
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
            "PostgreSQL query response: {} columns, {} rows",
            columns.len(),
            rows.len()
        );

        let _ = self.status_tx.send(format!(
            "[DEBUG] PostgreSQL → Result set: {} columns, {} rows",
            columns.len(),
            rows.len()
        ));

        Ok(ActionResult::Custom {
            name: "postgresql_query_response".to_string(),
            data: json!({
                "columns": columns,
                "rows": rows
            }),
        })
    }

    fn execute_postgresql_error_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let severity = action
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("ERROR");

        let code = action
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("XX000");

        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");

        debug!(
            "PostgreSQL error response: {} {} - {}",
            severity, code, message
        );

        let _ = self.status_tx.send(format!(
            "[DEBUG] PostgreSQL ✗ {} {}: {}",
            severity, code, message
        ));

        Ok(ActionResult::Custom {
            name: "postgresql_error".to_string(),
            data: json!({
                "severity": severity,
                "code": code,
                "message": message
            }),
        })
    }

    fn execute_postgresql_ok_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let tag = action.get("tag").and_then(|v| v.as_str()).unwrap_or("OK");

        debug!("PostgreSQL OK response: {}", tag);

        let _ = self
            .status_tx
            .send(format!("[DEBUG] PostgreSQL → OK: {}", tag));

        Ok(ActionResult::Custom {
            name: "postgresql_ok".to_string(),
            data: json!({
                "tag": tag
            }),
        })
    }
}

/// Action definition: Send PostgreSQL query response
pub fn postgresql_query_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "postgresql_query_response".to_string(),
        description: "The answer to any statement that returns rows - SELECT (including \
                      SELECT 1, SELECT current_user, SELECT version()), SHOW, VALUES, WITH. \
                      A single value is one column and one row. Never answer a SELECT with \
                      postgresql_ok_response: a command tag carries no rows, so the client \
                      prints the tag and never sees the value. One response per query."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "columns".to_string(),
                type_hint: "array".to_string(),
                description: "Array of column definitions. Each column needs 'name' and 'type'. \
                              Recognised types: int2/smallint, int4/int/integer, int8/bigint, \
                              float4/real, float8/double, bool/boolean, date, time, timestamp, \
                              text, varchar (anything else is sent as varchar). Rows shorter than \
                              the column list are padded with NULLs; extra values are dropped"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "rows".to_string(),
                type_hint: "array".to_string(),
                description:
                    "Array of rows. Each row is an array of values matching the column order"
                        .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "postgresql_query_response",
            "columns": [{"name": "id", "type": "int4"}, {"name": "name", "type": "text"}],
            "rows": [[1, "Alice"], [2, "Bob"]]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> PostgreSQL {columns_len} cols, {rows_len} rows")
                .with_debug("PostgreSQL query_response: {columns_len} columns, {rows_len} rows"),
        ),
    }
}

/// Action definition: Send PostgreSQL error response
pub fn postgresql_error_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "postgresql_error_response".to_string(),
        description: "Send an error response to the client".to_string(),
        parameters: vec![
            Parameter {
                name: "severity".to_string(),
                type_hint: "string".to_string(),
                description: "Error severity (ERROR, FATAL, PANIC, WARNING, NOTICE, DEBUG, INFO, LOG)".to_string(),
                required: false,
            },
            Parameter {
                name: "code".to_string(),
                type_hint: "string".to_string(),
                description: "PostgreSQL error code (e.g. '42P01' for undefined_table, '42601' for syntax_error)".to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Error message to display to the client".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "postgresql_error_response",
            "severity": "ERROR",
            "code": "42P01",
            "message": "relation \"table_name\" does not exist"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> PostgreSQL {severity} {code}: {message}")
                .with_debug("PostgreSQL error_response: {severity} {code}"),
        ),
    }
}

/// Action definition: Send PostgreSQL command complete response
pub fn postgresql_ok_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "postgresql_ok_response".to_string(),
        description: "Command-complete tag for a statement that returns no rows: INSERT, \
                      UPDATE, DELETE, CREATE, SET, BEGIN. Never for SELECT or SHOW - those \
                      are answered with postgresql_query_response. The tag names the statement \
                      that ran (a SELECT answered here would print 'INSERT 0 1')."
            .to_string(),
        parameters: vec![Parameter {
            name: "tag".to_string(),
            type_hint: "string".to_string(),
            description: "Command tag (e.g. 'INSERT 0 1', 'UPDATE 3', 'DELETE 2', 'CREATE TABLE')"
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "postgresql_ok_response",
            "tag": "INSERT 0 1"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> PostgreSQL OK: {tag}")
                .with_debug("PostgreSQL ok_response: {tag}"),
        ),
    }
}

/// Action definition: Close current PostgreSQL connection
pub fn close_this_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_this_connection".to_string(),
        description: "Close the current PostgreSQL connection".to_string(),
        parameters: vec![],
        example: json!({"type": "close_this_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("PostgreSQL connection closed")
                .with_debug("PostgreSQL close_this_connection"),
        ),
    }
}

// ============================================================================
// PostgreSQL Action Constants
// ============================================================================

/// PostgreSQL query response action constant
pub static POSTGRESQL_QUERY_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| ActionDefinition {
        name: "postgresql_query_response".to_string(),
        description: "The answer to any statement that returns rows - SELECT (including \
                      SELECT 1, SELECT current_user, SELECT version()), SHOW, VALUES, WITH. \
                      A single value is one column and one row. Never answer a SELECT with \
                      postgresql_ok_response: a command tag carries no rows, so the client \
                      prints the tag and never sees the value. One response per query."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "columns".to_string(),
                type_hint: "array".to_string(),
                description: "Array of column definitions. Each column needs 'name' and 'type'. \
                              Recognised types: int2/smallint, int4/int/integer, int8/bigint, \
                              float4/real, float8/double, bool/boolean, date, time, timestamp, \
                              text, varchar (anything else is sent as varchar). Rows shorter than \
                              the column list are padded with NULLs; extra values are dropped"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "rows".to_string(),
                type_hint: "array".to_string(),
                description:
                    "Array of rows. Each row is an array of values matching the column order"
                        .to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "postgresql_query_response",
            "columns": [{"name": "id", "type": "int4"}, {"name": "name", "type": "text"}],
            "rows": [[1, "Alice"], [2, "Bob"]]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> PostgreSQL {columns_len} cols, {rows_len} rows")
                .with_debug("PostgreSQL query_response: {columns_len} columns, {rows_len} rows"),
        ),
    });

/// PostgreSQL error response action constant
pub static POSTGRESQL_ERROR_RESPONSE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| {
    ActionDefinition {
        name: "postgresql_error_response".to_string(),
        description: "Send an error response to the client".to_string(),
        parameters: vec![
            Parameter {
                name: "severity".to_string(),
                type_hint: "string".to_string(),
                description: "Error severity (ERROR, FATAL, PANIC, WARNING, NOTICE, DEBUG, INFO, LOG)".to_string(),
                required: false,
            },
            Parameter {
                name: "code".to_string(),
                type_hint: "string".to_string(),
                description: "PostgreSQL error code (e.g. '42P01' for undefined_table, '42601' for syntax_error)".to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Error message to display to the client".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "postgresql_error_response",
            "severity": "ERROR",
            "code": "42P01",
            "message": "relation \"table_name\" does not exist"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> PostgreSQL {severity} {code}: {message}")
                .with_debug("PostgreSQL error_response: {severity} {code}"),
        ),
    }
});

/// PostgreSQL OK response action constant
pub static POSTGRESQL_OK_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| ActionDefinition {
        name: "postgresql_ok_response".to_string(),
        description: "Command-complete tag for a statement that returns no rows: INSERT, \
                      UPDATE, DELETE, CREATE, SET, BEGIN. Never for SELECT or SHOW - those \
                      are answered with postgresql_query_response. The tag names the statement \
                      that ran (a SELECT answered here would print 'INSERT 0 1')."
            .to_string(),
        parameters: vec![Parameter {
            name: "tag".to_string(),
            type_hint: "string".to_string(),
            description: "Command tag (e.g. 'INSERT 0 1', 'UPDATE 3', 'DELETE 2', 'CREATE TABLE')"
                .to_string(),
            required: true,
        }],
        example: json!({
            "type": "postgresql_ok_response",
            "tag": "INSERT 0 1"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> PostgreSQL OK: {tag}")
                .with_debug("PostgreSQL ok_response: {tag}"),
        ),
    });

/// PostgreSQL close connection action constant
pub static POSTGRESQL_CLOSE_CONNECTION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| ActionDefinition {
        name: "close_this_connection".to_string(),
        description: "Close the current PostgreSQL connection".to_string(),
        parameters: vec![],
        example: json!({"type": "close_this_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("PostgreSQL connection closed")
                .with_debug("PostgreSQL close_this_connection"),
        ),
    });

// ============================================================================
// PostgreSQL Event Type Constants
// ============================================================================

/// PostgreSQL query event - triggered when client sends a query
pub static POSTGRESQL_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "postgresql_query",
        "PostgreSQL query received from client",
        json!({"type": "placeholder", "event_id": "postgresql_query"}),
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
        POSTGRESQL_QUERY_RESPONSE_ACTION.clone(),
        POSTGRESQL_ERROR_RESPONSE_ACTION.clone(),
        POSTGRESQL_OK_RESPONSE_ACTION.clone(),
        POSTGRESQL_CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("PostgreSQL {client_ip}: {preview(query,80)}")
            .with_debug("PostgreSQL query from {client_ip}:{client_port}")
            .with_trace("PostgreSQL: {json_pretty(.)}"),
    )
});

/// The `answer_with` event field for `sql`, or `None` when its first keyword does not say.
///
/// See `crate::utils::sql`: the real-model eval answered `SELECT current_user` with the command
/// tag `INSERT 0 1`, copied from the ok action's example, so the client printed a tag instead of
/// the value it asked for.
pub fn answer_with_for_query(sql: &str) -> Option<&'static str> {
    use crate::utils::sql::{statement_shape, StatementShape};
    match statement_shape(sql) {
        StatementShape::Rows => Some(
            "postgresql_query_response: this statement returns rows - columns and rows, one \
             column and one row for a single value - never a command tag",
        ),
        StatementShape::NoRows => Some(
            "postgresql_ok_response: this statement returns no rows - the command tag of what \
             ran, e.g. 'INSERT 0 1', 'UPDATE 3', 'SET'",
        ),
        StatementShape::Unknown => None,
    }
}

/// Get PostgreSQL event types
pub fn get_postgresql_event_types() -> Vec<EventType> {
    vec![POSTGRESQL_QUERY_EVENT.clone()]
}

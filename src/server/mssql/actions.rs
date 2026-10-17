//! MSSQL protocol actions implementation

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

/// MSSQL protocol action handler
pub struct MssqlProtocol {
    _connection_id: ConnectionId,
    _app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
}

impl MssqlProtocol {
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
impl Protocol for MssqlProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![crate::llm::actions::ParameterDefinition {
            name: "send_first".to_string(),
            type_hint: "boolean".to_string(),
            description:
                "Unsupported by this server and refused if set to true. MSSQL: the client opens with a PRELOGIN packet and the server answers it; TDS has no server-first message."
                    .to_string(),
            required: false,
            example: serde_json::json!(false),
            default: None,
        }]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // No user-triggered actions. (A `list_mssql_connections` action used to be declared
        // here; its executor returned a hardcoded empty list, so it only ever misled the model.)
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            mssql_query_response_action(),
            mssql_error_response_action(),
            mssql_ok_response_action(),
            MSSQL_LOGIN_ACK_ACTION.clone(),
            close_this_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "MSSQL"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_mssql_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TDS>MSSQL"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["mssql", "sql server", "tds"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            // Beta: exercised against a real, independent client — tiberius —
            // covering login and queries driven by a real TDS client. Not Stable: Stable additionally wants spec
            // compliance and scripting support reviewed, which has not been done here.
            .state(DevelopmentState::Beta)
            .well_known_port(1433)
            .implementation("Manual TDS 7.4 implementation (pre-login, login, SQL batch, RPC)")
            .llm_control("Query responses (result sets, errors, completion)")
            .e2e_testing("tiberius client crate")
            .notes(
                "No credential verification and no TLS (pre-login advertises ENCRYPT_NOT_SUP): \
                 the LOGIN7 password is never checked, and is deliberately not parsed into the \
                 mssql_login event. Admission is still a decision - it requires an explicit \
                 mssql_login_ack, and silence, a model refusal and a backend failure all refuse \
                 with 18456. RPC parameters are not decoded - the SQL text is recovered \
                 heuristically from the packet, so parameterised queries arrive with their \
                 placeholders intact",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Microsoft SQL Server (MSSQL) database server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an MSSQL server on port 1433"
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: answer every T-SQL query with a single-column result
        // set (one INT column, value 1), no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
if data["event_type_id"] == "mssql_query":
    actions = [{"type": "mssql_query_response",
                "columns": [{"name": "result", "type": "INT"}],
                "rows": [[1]]}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles all MSSQL responses intelligently
            json!({
                "type": "open_server",
                "port": 1433,
                "base_stack": "mssql",
                "instruction": "MSSQL database server answering SQL queries"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_server",
                "port": 1433,
                "base_stack": "mssql",
                "event_handlers": [{
                    "event_pattern": "mssql_query",
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
                "port": 1433,
                "base_stack": "mssql",
                "event_handlers": [{
                    "event_pattern": "mssql_query",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "mssql_query_response",
                            "columns": [{"name": "result", "type": "INT"}],
                            "rows": [[1]]
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for MssqlProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::mssql::MssqlServer;
            // `send_first` stays declared so a caller that passes `false` still validates - an
            // undeclared key is refused outright - but `true` is refused rather than ignored.
            // It was read here, threaded through spawn, and dropped at the far end as
            // `_send_first`: a knob advertised to the model, plumbed through three hops, and
            // silently doing nothing. MSSQL: the client opens with a PRELOGIN packet and the server answers it; TDS has no server-first message.
            let send_first = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_bool("send_first"))
                .transpose()?
                .flatten()
                .unwrap_or(false);
            if send_first {
                return Err(anyhow::anyhow!(
                    "send_first is not supported by the MSSQL server: the client opens with a PRELOGIN packet and the server answers it; TDS has no server-first message"
                ));
            }

            MssqlServer::spawn_with_llm_actions(
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
            "mssql_query_response" => self.execute_mssql_query_response(action),
            "mssql_error_response" => self.execute_mssql_error_response(action),
            "mssql_ok_response" => self.execute_mssql_ok_response(action),
            "mssql_login_ack" => {
                let database = action
                    .get("database")
                    .and_then(|v| v.as_str())
                    .unwrap_or("master")
                    .to_string();
                Ok(ActionResult::Custom {
                    name: "mssql_login_ack".to_string(),
                    data: json!({ "database": database }),
                })
            }
            "close_this_connection" => Ok(ActionResult::CloseConnection),
            // Deliberately not advertised (it is in neither `get_sync_actions()` nor any
            // event's action list, so the model's tool list is unchanged): the dashboard's
            // `[ disconnect this peer ]` injects a bare `{"type": "close_connection"}` through
            // the peer handle, and without this arm that button fails as an unknown action.
            // `tcp` accepts both names for the same reason.
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown MSSQL action: {}", action_type)),
        }
    }
}

impl MssqlProtocol {
    fn execute_mssql_query_response(&self, action: serde_json::Value) -> Result<ActionResult> {
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
            "MSSQL query response: {} columns, {} rows",
            columns.len(),
            rows.len()
        );

        let _ = self.status_tx.send(format!(
            "[DEBUG] MSSQL → Result set: {} columns, {} rows",
            columns.len(),
            rows.len()
        ));

        // Return a custom action result with the query response data
        Ok(ActionResult::Custom {
            name: "mssql_query_response".to_string(),
            data: json!({
                "columns": columns,
                "rows": rows
            }),
        })
    }

    fn execute_mssql_error_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Range-checked, not narrowed. Both fields were `as_u64()… as` a smaller type, which
        // wraps in silence, and for `severity` the wrap lands on the one value that changes
        // what the packet says: `256 as u8` is `0`, and MS-TDS reserves 10-and-below for
        // *informational* messages — so a model refusing a statement at severity 20 delivered
        // the mildest notice the token can carry. Refusing beats clamping: 25 is not what the
        // model asked for either, and the message is what the repair loop reads.
        let error_number = match action.get("error_number") {
            None => 50000,
            Some(v) if v.is_null() => 50000,
            Some(v) => {
                let raw = v
                    .as_u64()
                    .with_context(|| format!("'error_number' must be a number, got {v}"))?;
                u32::try_from(raw).map_err(|_| {
                    anyhow::anyhow!(
                        "'error_number' {raw} does not fit the 32-bit message id TDS carries. \
                         SQL Server uses 50000+ for user-defined errors."
                    )
                })?
            }
        };

        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");

        let severity = match action.get("severity") {
            None => 16,
            Some(v) if v.is_null() => 16,
            Some(v) => {
                let raw = v
                    .as_u64()
                    .with_context(|| format!("'severity' must be a number, got {v}"))?;
                if raw > 25 {
                    return Err(anyhow::anyhow!(
                        "'severity' {raw} is outside the TDS severity range 0-25. 11-16 are \
                         errors the caller can correct, 17-19 resource errors, 20-25 fatal; \
                         10 and below read as an informational message rather than a failure."
                    ));
                }
                raw as u8
            }
        };

        debug!("MSSQL error response: {} - {}", error_number, message);

        let _ = self.status_tx.send(format!(
            "[DEBUG] MSSQL ✗ Error {}: {}",
            error_number, message
        ));

        Ok(ActionResult::Custom {
            name: "mssql_error".to_string(),
            data: json!({
                "error_number": error_number,
                "message": message,
                "severity": severity
            }),
        })
    }

    fn execute_mssql_ok_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let rows_affected = action
            .get("rows_affected")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        debug!("MSSQL OK response: rows_affected={}", rows_affected);

        let _ = self.status_tx.send(format!(
            "[DEBUG] MSSQL → OK: {} rows affected",
            rows_affected
        ));

        Ok(ActionResult::Custom {
            name: "mssql_ok".to_string(),
            data: json!({
                "rows_affected": rows_affected
            }),
        })
    }
}

/// Action definition: Send MSSQL query response
pub fn mssql_query_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "mssql_query_response".to_string(),
        description: "Send a result set in response to a SELECT query".to_string(),
        parameters: vec![
            Parameter {
                name: "columns".to_string(),
                type_hint: "array".to_string(),
                description: "Array of column definitions. Each column needs 'name' and 'type'. \
                              Recognised types: TINYINT, SMALLINT, INT/INTEGER, BIGINT (sent as \
                              binary integers), BIT/BOOL (sent as a bit), FLOAT/REAL/DOUBLE/DECIMAL \
                              (sent as a 64-bit float), and NVARCHAR/VARCHAR/anything else (sent as \
                              Unicode text, max 4000 characters). JSON null becomes SQL NULL. Rows \
                              shorter than the column list are padded with NULLs".to_string(),
                required: true,
            },
            Parameter {
                name: "rows".to_string(),
                type_hint: "array".to_string(),
                description: "Array of rows. Each row is an array of values matching the column order".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "mssql_query_response",
            "columns": [{"name": "id", "type": "INT"}, {"name": "name", "type": "NVARCHAR"}],
            "rows": [[1, "Alice"], [2, "Bob"]]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> {columns_len} cols, {rows_len} rows")
                .with_debug("MSSQL result: {columns_len} columns, {rows_len} rows"),
        ),
    }
}

/// Action definition: Send MSSQL error response
pub fn mssql_error_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "mssql_error_response".to_string(),
        description: "Send an error response to the client".to_string(),
        parameters: vec![
            Parameter {
                name: "error_number".to_string(),
                type_hint: "number".to_string(),
                description:
                    "MSSQL error number (e.g. 207 for invalid column, 208 for invalid object)"
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Error message to display to the client".to_string(),
                required: true,
            },
            Parameter {
                name: "severity".to_string(),
                type_hint: "number".to_string(),
                description: "Error severity level (1-25, typically 16 for user errors)"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "mssql_error_response",
            "error_number": 208,
            "message": "Invalid object name 'table_name'",
            "severity": 16
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> error {error_number}: {message}")
                .with_debug("MSSQL error: code={error_number}, severity={severity}"),
        ),
    }
}

/// Action definition: Send MSSQL OK response
pub fn mssql_ok_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "mssql_ok_response".to_string(),
        description:
            "Send a completion response for INSERT, UPDATE, DELETE, or other non-SELECT queries"
                .to_string(),
        parameters: vec![Parameter {
            name: "rows_affected".to_string(),
            type_hint: "number".to_string(),
            description: "Number of rows affected by the query".to_string(),
            required: false,
        }],
        example: json!({
            "type": "mssql_ok_response",
            "rows_affected": 1
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> OK ({rows_affected} rows affected)")
                .with_debug("MSSQL OK: {rows_affected} rows affected"),
        ),
    }
}

/// Action definition: Close current MSSQL connection
pub fn close_this_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_this_connection".to_string(),
        description: "Close the current MSSQL connection".to_string(),
        parameters: vec![],
        example: json!({"type": "close_this_connection"}),
        log_template: Some(LogTemplate::new().with_info("-> connection closed")),
    }
}

// ============================================================================
// MSSQL Action Constants
// ============================================================================

/// MSSQL query response action constant
pub static MSSQL_QUERY_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| ActionDefinition {
        name: "mssql_query_response".to_string(),
        description: "Send a result set in response to a SELECT query".to_string(),
        parameters: vec![
            Parameter {
                name: "columns".to_string(),
                type_hint: "array".to_string(),
                description: "Array of column definitions. Each column needs 'name' and 'type' \
                              (TINYINT, SMALLINT, INT, BIGINT, BIT, FLOAT, NVARCHAR)"
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "rows".to_string(),
                type_hint: "array".to_string(),
                description: "Array of rows".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "mssql_query_response",
            "columns": [{"name": "id", "type": "INT"}, {"name": "name", "type": "NVARCHAR"}],
            "rows": [[1, "Alice"], [2, "Bob"]]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> MSSQL response ({rows_len} rows)")
                .with_debug("MSSQL mssql_query_response: columns={columns_len} rows={rows_len}"),
        ),
    });

/// MSSQL error response action constant
pub static MSSQL_ERROR_RESPONSE_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| {
    ActionDefinition {
        name: "mssql_error_response".to_string(),
        description: "Send an error response to the client".to_string(),
        parameters: vec![
            Parameter {
                name: "error_number".to_string(),
                type_hint: "number".to_string(),
                description: "MSSQL error number".to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Error message".to_string(),
                required: true,
            },
            Parameter {
                name: "severity".to_string(),
                type_hint: "number".to_string(),
                description: "Error severity level (1-25)".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "mssql_error_response",
            "error_number": 208,
            "message": "Invalid object name"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> MSSQL error {error_number}")
                .with_debug("MSSQL mssql_error_response: error_number={error_number} severity={severity} message='{message}'"),
        ),
    }
});

/// MSSQL OK response action constant
pub static MSSQL_OK_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| ActionDefinition {
        name: "mssql_ok_response".to_string(),
        description: "Send a completion response for non-SELECT queries".to_string(),
        parameters: vec![Parameter {
            name: "rows_affected".to_string(),
            type_hint: "number".to_string(),
            description: "Number of rows affected".to_string(),
            required: false,
        }],
        example: json!({
            "type": "mssql_ok_response",
            "rows_affected": 1
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> MSSQL OK ({rows_affected} rows affected)")
                .with_debug("MSSQL mssql_ok_response: rows_affected={rows_affected}"),
        ),
    });

/// MSSQL close connection action constant
pub static MSSQL_CLOSE_CONNECTION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| ActionDefinition {
        name: "close_this_connection".to_string(),
        description: "Close the current MSSQL connection".to_string(),
        parameters: vec![],
        example: json!({"type": "close_this_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> MSSQL close connection")
                .with_debug("MSSQL close_this_connection"),
        ),
    });

// ============================================================================
// MSSQL Event Type Constants
// ============================================================================

/// MSSQL query event - triggered when client sends a query
pub static MSSQL_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mssql_query",
        "MSSQL query received from client",
        json!({"type": "placeholder", "event_id": "mssql_query"}),
    )
    .with_parameters(vec![Parameter {
        name: "query".to_string(),
        type_hint: "string".to_string(),
        description: "The SQL query string sent by the client".to_string(),
        required: true,
    }])
    .with_actions(vec![
        MSSQL_QUERY_RESPONSE_ACTION.clone(),
        MSSQL_ERROR_RESPONSE_ACTION.clone(),
        MSSQL_OK_RESPONSE_ACTION.clone(),
        MSSQL_CLOSE_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} MSSQL {preview(query,50)} ({duration_ms}ms)")
            .with_debug("MSSQL query from {client_ip}: {preview(query,100)}")
            .with_trace("MSSQL full query: {query}"),
    )
});

/// Accept a TDS login.
///
/// Deliberately a separate action from `mssql_error_response` rather than a boolean on one
/// action: accept and reject then share no code path, which is the separation `src/server/radius/`
/// established and the root CLAUDE.md asks for. A model that says nothing accepts nothing.
pub static MSSQL_LOGIN_ACK_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| ActionDefinition {
        name: "mssql_login_ack".to_string(),
        description: "Accept the TDS login and let the session proceed. Without this action the \
                      login is refused - there is no implicit accept."
            .to_string(),
        parameters: vec![Parameter {
            name: "database".to_string(),
            type_hint: "string".to_string(),
            description: "Database context to report in the ENVCHANGE token (default 'master')"
                .to_string(),
            required: false,
        }],
        example: json!({
            "type": "mssql_login_ack",
            "database": "master"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> MSSQL login accepted (database {database})")
                .with_debug("MSSQL mssql_login_ack: database={database}"),
        ),
    });

/// MSSQL login event.
///
/// Until this existed there was no login event at all: `send_login_response` accepted every
/// TDS Login packet unconditionally, so an operator instruction like "only allow the user
/// `reporting`" could not be enforced and the model was never asked. Authentication is exactly
/// the decision the root CLAUDE.md says must not be made by default.
pub static MSSQL_LOGIN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mssql_login",
        "MSSQL client is attempting to log in",
        json!({"type": "placeholder", "event_id": "mssql_login"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "username".to_string(),
            type_hint: "string".to_string(),
            description: "Username from the LOGIN7 packet (empty when the client sent none)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "database".to_string(),
            type_hint: "string".to_string(),
            description: "Database the client asked for, if any".to_string(),
            required: false,
        },
        Parameter {
            name: "app_name".to_string(),
            type_hint: "string".to_string(),
            description: "Application name the client reported, if any".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        MSSQL_LOGIN_ACK_ACTION.clone(),
        MSSQL_ERROR_RESPONSE_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("{client_ip} MSSQL login attempt user={username} db={database}")
            .with_debug("MSSQL login from {client_ip}: user={username} app={app_name}"),
    )
});

/// Get MSSQL event types
pub fn get_mssql_event_types() -> Vec<EventType> {
    vec![MSSQL_QUERY_EVENT.clone(), MSSQL_LOGIN_EVENT.clone()]
}

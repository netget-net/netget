//! Snowflake protocol actions implementation
//!
//! Snowflake's client/driver protocol is HTTPS + JSON: the driver POSTs to a small
//! set of REST endpoints (`/session/v1/login-request`, `/queries/v1/query-request`,
//! `/session/logout-request`, `/session/token-request`) and reads a JSON envelope
//! back. NetGet serves those endpoints and lets the LLM play the warehouse: it
//! decides the session token minted at login and the rowset returned for a query.
//!
//! **There is no storage.** No tables, no rows, no session table in Rust. The model
//! answers every request. Because there is no session store, the query endpoint
//! cannot *validate* a token against issued ones — it surfaces whether an
//! `Authorization` token was presented and leaves the decision to the model.

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

/// Snowflake protocol action handler.
///
/// Like the other database protocols this is a thin, stateless description: it
/// carries no session table (there is no storage), only the channel used for dual
/// logging when an action is executed.
pub struct SnowflakeProtocol {
    _connection_id: ConnectionId,
    _app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
}

impl SnowflakeProtocol {
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

impl Protocol for SnowflakeProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        // No startup parameters: every request is answered by the model, and there
        // is nothing to configure at spawn time. Declaring a parameter that is never
        // read is a documented trap (the model tries to use it), so declare none.
        vec![]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // Snowflake is purely reactive: the model answers login/query/session events.
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            snowflake_login_success_action(),
            snowflake_query_response_action(),
            snowflake_session_response_action(),
            snowflake_error_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "Snowflake"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_snowflake_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>Snowflake"
    }

    fn keywords(&self) -> Vec<&'static str> {
        // Distinctive, multi-word keywords — no bare "db"/"sql"/"database".
        vec!["snowflake", "snowflake warehouse", "snowflake data cloud"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Hand-written Snowflake REST/JSON endpoints over hyper (login, query, session)")
            .llm_control("Session tokens at login, rowset/rowtype for queries, error envelopes")
            .e2e_testing("tests/server/snowflake/real_client_test.rs drives the server with snowflake-connector-python 4.8.0, Snowflake's official Python driver (gzipped request bodies): a login the model grants and one it refuses (the driver raises 390100), a six-column rowset typed by the driver's own JSON converters (FIXED with a scale, BOOLEAN, DATE, TIMESTAMP_NTZ, NULL), a query error raised with the model's errno and SQLSTATE, and the driver's POST /session?delete=true logout. e2e_test.rs and llm_failure_test.rs drive the envelopes with reqwest")
            .notes(
                "HTTP/JSON only; TLS termination is out of scope (real drivers use HTTPS — front with a \
                 TLS proxy if needed). One real driver so far (snowflake-connector-python over plain \
                 HTTP); JDBC, ODBC and gosnowflake are untested, and results are JSON only (no Arrow, \
                 no chunks). No session store, so tokens are not validated against issued ones. \
                 Fail-closed: an LLM outage on login is a refusal (no token issued), never a \
                 success-shaped empty result.",
            )
            .max_inbound_bytes(crate::server::snowflake::MAX_REQUEST_BYTES)
            .request_only("The Snowflake API is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "Snowflake data-warehouse server (REST/JSON login + query protocol)"
    }

    fn example_prompt(&self) -> &'static str {
        "Start a Snowflake server on port 8085 that logs clients in and answers SELECT queries"
    }

    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: answer every SQL query with a single-column "OK"
        // rowset, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
if data["event_type_id"] == "snowflake_query":
    actions = [{"type": "snowflake_query_response",
                "rowtype": [{"name": "STATUS", "type": "text"}],
                "rowset": [["OK"]]}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 8085,
                "base_stack": "snowflake",
                "instruction": "Snowflake warehouse: accept logins and answer SQL queries with plausible rowsets"
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 8085,
                "base_stack": "snowflake",
                "event_handlers": [{
                    "event_pattern": "snowflake_query",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": script
                    }
                }]
            }),
            // Static mode
            json!({
                "type": "open_server",
                "port": 8085,
                "base_stack": "snowflake",
                "event_handlers": [{
                    "event_pattern": "snowflake_login",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "snowflake_login_success",
                            "token": "SESSION_TOKEN_ABC",
                            "master_token": "MASTER_TOKEN_ABC",
                            "session_id": 100
                        }]
                    }
                }]
            }),
        )
    }
}

impl Server for SnowflakeProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::snowflake::SnowflakeServer;
            SnowflakeServer::spawn_with_llm_actions(
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
            "snowflake_login_success" => self.execute_login_success(action),
            "snowflake_query_response" => self.execute_query_response(action),
            "snowflake_session_response" => self.execute_session_response(action),
            "snowflake_error" => self.execute_error(action),
            _ => Err(anyhow::anyhow!("Unknown Snowflake action: {}", action_type)),
        }
    }
}

impl SnowflakeProtocol {
    fn execute_login_success(&self, action: serde_json::Value) -> Result<ActionResult> {
        let token = action
            .get("token")
            .and_then(|v| v.as_str())
            .context("Missing 'token' in snowflake_login_success")?
            .to_string();
        let master_token = action
            .get("master_token")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let session_id = action.get("session_id").cloned();
        let validity_seconds = action.get("validity_seconds").and_then(|v| v.as_u64());

        debug!("Snowflake login success: session token minted");
        let _ = self
            .status_tx
            .send("[DEBUG] Snowflake → login success (token issued)".to_string());

        Ok(ActionResult::Custom {
            name: "snowflake_login_success".to_string(),
            data: json!({
                "token": token,
                "master_token": master_token,
                "session_id": session_id,
                "validity_seconds": validity_seconds,
            }),
        })
    }

    fn execute_query_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let rowtype = action
            .get("rowtype")
            .and_then(|v| v.as_array())
            .context("Missing 'rowtype' array in snowflake_query_response")?;
        let rowset = action
            .get("rowset")
            .and_then(|v| v.as_array())
            .context("Missing 'rowset' array in snowflake_query_response")?;
        let query_id = action
            .get("query_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        debug!(
            "Snowflake query response: {} columns, {} rows",
            rowtype.len(),
            rowset.len()
        );
        let _ = self.status_tx.send(format!(
            "[DEBUG] Snowflake → rowset: {} columns, {} rows",
            rowtype.len(),
            rowset.len()
        ));

        Ok(ActionResult::Custom {
            name: "snowflake_query_response".to_string(),
            data: json!({
                "rowtype": rowtype,
                "rowset": rowset,
                "query_id": query_id,
            }),
        })
    }

    fn execute_session_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let data = action.get("data").cloned().unwrap_or(json!({}));
        debug!("Snowflake session response");
        let _ = self
            .status_tx
            .send("[DEBUG] Snowflake → session response".to_string());
        Ok(ActionResult::Custom {
            name: "snowflake_session_response".to_string(),
            data: json!({ "data": data }),
        })
    }

    fn execute_error(&self, action: serde_json::Value) -> Result<ActionResult> {
        let code = action
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("000603")
            .to_string();
        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error")
            .to_string();
        let sql_state = action
            .get("sql_state")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        debug!("Snowflake error response: {} - {}", code, message);
        let _ = self
            .status_tx
            .send(format!("[DEBUG] Snowflake ✗ error {}: {}", code, message));
        let mut data = json!({ "code": code, "message": message });
        if let Some(state) = sql_state {
            data["sql_state"] = json!(state);
        }
        Ok(ActionResult::Custom {
            name: "snowflake_error".to_string(),
            data,
        })
    }
}

// ============================================================================
// Action definitions
// ============================================================================

/// `snowflake_login_success` — issue a session token in response to a login.
pub fn snowflake_login_success_action() -> ActionDefinition {
    ActionDefinition {
        name: "snowflake_login_success".to_string(),
        description: "Authenticate the client and issue a Snowflake session token. Only emit this \
            when the login should succeed; to refuse a login use snowflake_error instead (never \
            leave the event unanswered — an unanswered login is treated as a refusal)."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "token".to_string(),
                type_hint: "string".to_string(),
                description: "The session token the driver will send back as \
                    Authorization: Snowflake Token=\"...\" on subsequent query requests."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "master_token".to_string(),
                type_hint: "string".to_string(),
                description: "Master token used by the driver to renew the session (optional)."
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "session_id".to_string(),
                type_hint: "number".to_string(),
                description: "Numeric session id (optional)".to_string(),
                required: false,
            },
            Parameter {
                name: "validity_seconds".to_string(),
                type_hint: "number".to_string(),
                description: "Session token validity in seconds (optional, default 3600)"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "snowflake_login_success",
            "token": "ver:1-hint:abc-ETMsDgAAA...",
            "master_token": "ver:1-hint:def-ETMsDgAAA...",
            "session_id": 123456789,
            "validity_seconds": 3600
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Snowflake login OK (session {session_id})")
                .with_debug("Snowflake snowflake_login_success: session_id={session_id}"),
        ),
    }
}

/// `snowflake_query_response` — return a result set for a SQL query.
pub fn snowflake_query_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "snowflake_query_response".to_string(),
        description: "Return a result set for a SQL query. `rowtype` describes the columns and \
            `rowset` is the rows. Snowflake's JSON result format transmits every value as a \
            string, so all cell values are stringified on the wire."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "rowtype".to_string(),
                type_hint: "array".to_string(),
                description: "Array of column descriptors. Each is an object with at least \
                    'name' and 'type' (Snowflake logical types: text, fixed, real, boolean, date, \
                    time, timestamp_ntz, variant, ...). Optional fields (nullable, length, \
                    precision, scale) are passed through; sensible defaults are filled in."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "rowset".to_string(),
                type_hint: "array".to_string(),
                description: "Array of rows; each row is an array of cell values matching the \
                    column order. Values are sent as strings (Snowflake JSON result format)."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "query_id".to_string(),
                type_hint: "string".to_string(),
                description: "Optional query id (UUID) echoed back to the driver".to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "snowflake_query_response",
            "rowtype": [
                {"name": "ID", "type": "fixed"},
                {"name": "NAME", "type": "text"}
            ],
            "rowset": [["1", "Alice"], ["2", "Bob"]],
            "query_id": "01b2c3d4-0000-0000-0000-000000000001"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Snowflake {rowtype_len} cols, {rowset_len} rows")
                .with_debug(
                    "Snowflake snowflake_query_response: {rowtype_len} cols, {rowset_len} rows",
                ),
        ),
    }
}

/// `snowflake_session_response` — answer a logout / token-renew request.
pub fn snowflake_session_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "snowflake_session_response".to_string(),
        description: "Acknowledge a session-management request (logout or token renewal) with a \
            success envelope. For logout, omit `data`. For token renewal, put the renewed \
            {sessionToken, masterToken, validityInSeconds} in `data`."
            .to_string(),
        parameters: vec![Parameter {
            name: "data".to_string(),
            type_hint: "object".to_string(),
            description: "Optional data object placed in the response 'data' field (e.g. renewed \
                tokens for a token-request). Omit for a plain logout acknowledgement."
                .to_string(),
            required: false,
        }],
        example: json!({
            "type": "snowflake_session_response",
            "data": {"sessionToken": "ver:1-...", "validityInSeconds": 3600}
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Snowflake session OK")
                .with_debug("Snowflake snowflake_session_response"),
        ),
    }
}

/// `snowflake_error` — refuse a login/query/session with a Snowflake error envelope.
pub fn snowflake_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "snowflake_error".to_string(),
        description: "Refuse the current request with a Snowflake error envelope (success:false). \
            This is the only way to deny a login or reject a query. The client receives HTTP 200 \
            with success:false and the code/message you provide."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "string".to_string(),
                description: "Snowflake error code string, e.g. \"390100\" (incorrect username or \
                    password), \"390114\" (authentication token expired), \"002003\" (object does \
                    not exist), \"001003\" (SQL compilation error)."
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Human-readable error message shown to the client".to_string(),
                required: true,
            },
            Parameter {
                name: "sql_state".to_string(),
                type_hint: "string".to_string(),
                description: "Five-character SQLSTATE for a refused query, e.g. \"42S02\" \
                    (table not found) or \"42000\" (syntax error); drivers raise it with the \
                    error. Ignored for a refused login."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "snowflake_error",
            "code": "390100",
            "message": "Incorrect username or password was specified."
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Snowflake ERR {code}: {message}")
                .with_debug("Snowflake snowflake_error: code={code}, message={message}"),
        ),
    }
}

// ============================================================================
// Action constants (attached to event types)
// ============================================================================

pub static SNOWFLAKE_LOGIN_SUCCESS_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(snowflake_login_success_action);
pub static SNOWFLAKE_QUERY_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(snowflake_query_response_action);
pub static SNOWFLAKE_SESSION_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(snowflake_session_response_action);
pub static SNOWFLAKE_ERROR_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(snowflake_error_action);

// ============================================================================
// Event types
// ============================================================================

/// Emitted on `POST /session/v1/login-request` — the client is authenticating.
pub static SNOWFLAKE_LOGIN_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "snowflake_login",
        "Snowflake client login request",
        json!({
            "type": "snowflake_login_success",
            "token": "SESSION_TOKEN",
            "session_id": 100
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "login_name".to_string(),
            type_hint: "string".to_string(),
            description: "The username the client is logging in as".to_string(),
            required: false,
        },
        Parameter {
            name: "account".to_string(),
            type_hint: "string".to_string(),
            description: "The Snowflake account name the client is targeting".to_string(),
            required: false,
        },
        Parameter {
            name: "client_app_id".to_string(),
            type_hint: "string".to_string(),
            description: "The driver/app id (e.g. PythonConnector, JDBC)".to_string(),
            required: false,
        },
        Parameter {
            name: "client_app_version".to_string(),
            type_hint: "string".to_string(),
            description: "The driver/app version".to_string(),
            required: false,
        },
        Parameter {
            name: "has_password".to_string(),
            type_hint: "boolean".to_string(),
            description: "True if a password was supplied in the login request".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        SNOWFLAKE_LOGIN_SUCCESS_ACTION.clone(),
        SNOWFLAKE_ERROR_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Snowflake login: {login_name}@{account}")
            .with_debug("Snowflake login request: {json_pretty(.)}"),
    )
});

/// Emitted on `POST /queries/v1/query-request` — the client runs SQL.
pub static SNOWFLAKE_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "snowflake_query",
        "Snowflake SQL query request",
        json!({
            "type": "snowflake_query_response",
            "rowtype": [{"name": "COL", "type": "text"}],
            "rowset": [["value"]]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "sql_text".to_string(),
            type_hint: "string".to_string(),
            description: "The SQL statement the client wants to run".to_string(),
            required: true,
        },
        Parameter {
            name: "has_auth_token".to_string(),
            type_hint: "boolean".to_string(),
            description: "True if the client presented an Authorization session token. There is \
                no session store, so the token is not validated — decide based on this signal."
                .to_string(),
            required: false,
        },
        Parameter {
            name: "request_id".to_string(),
            type_hint: "string".to_string(),
            description: "The requestId query parameter, if present".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        SNOWFLAKE_QUERY_RESPONSE_ACTION.clone(),
        SNOWFLAKE_ERROR_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Snowflake query: {preview(sql_text,80)}")
            .with_debug("Snowflake query: {sql_text}"),
    )
});

/// Emitted on `POST /session/logout-request` and `POST /session/token-request`.
pub static SNOWFLAKE_SESSION_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "snowflake_session",
        "Snowflake session management request (logout or token renewal)",
        json!({
            "type": "snowflake_session_response"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "Either \"logout\" or \"token_renew\"".to_string(),
            required: true,
        },
        Parameter {
            name: "has_auth_token".to_string(),
            type_hint: "boolean".to_string(),
            description: "True if the client presented an Authorization session token".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        SNOWFLAKE_SESSION_RESPONSE_ACTION.clone(),
        SNOWFLAKE_ERROR_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Snowflake session: {operation}")
            .with_debug("Snowflake session request: {operation}"),
    )
});

/// All Snowflake event types.
pub fn get_snowflake_event_types() -> Vec<EventType> {
    vec![
        SNOWFLAKE_LOGIN_EVENT.clone(),
        SNOWFLAKE_QUERY_EVENT.clone(),
        SNOWFLAKE_SESSION_EVENT.clone(),
    ]
}

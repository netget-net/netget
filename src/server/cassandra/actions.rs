//! Cassandra protocol actions implementation

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

/// Cassandra protocol action handler
pub struct CassandraProtocol {
    _connection_id: ConnectionId,
    _app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
}

impl CassandraProtocol {
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
impl Protocol for CassandraProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        // Deliberately empty. `send_first` was declared here and parsed in `spawn()`, but it
        // reached `CassandraServer::spawn_with_llm_actions` as `_send_first` and was
        // discarded — and could never have been honoured: the native protocol is strictly
        // client-first, a driver opens with STARTUP or OPTIONS and any unsolicited server
        // frame is a protocol violation. Undeclaring it makes `server_startup` log an
        // explicit "does not support send_first" instead of accepting a knob that does
        // nothing. Same exit as `nntp`, `elasticsearch` and `mongodb`.
        vec![]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // No user-triggered actions. `list_cassandra_connections` used to be declared here and
        // only ever returned ActionResult::NoAction over a connection map that was never
        // populated, so it did nothing on any path.
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            cassandra_ready_action(),
            cassandra_authenticate_action(),
            cassandra_supported_action(),
            cassandra_result_rows_action(),
            cassandra_prepared_action(),
            cassandra_auth_success_action(),
            cassandra_error_action(),
            close_this_connection_action(),
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "Cassandra"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_cassandra_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>Cassandra"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["cassandra", "cql"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            // Beta: exercised against a real, independent client — scylla —
            // covering the official Rust CQL driver completing a session and statements. Not Stable: Stable additionally wants spec
            // compliance and scripting support reviewed, which has not been done here.
            .state(DevelopmentState::Beta)
            .well_known_port(9042)
            .implementation(
                "cassandra-protocol v3.0 for frame parsing; response bodies built by hand. \
                 Protocol v4 only.",
            )
            .llm_control(
                "STARTUP/OPTIONS/QUERY/PREPARE/EXECUTE and, when the handler answers STARTUP \
                 with cassandra_authenticate, SASL PLAIN auth.",
            )
            .e2e_testing("scylla client (real driver) in tests/server/cassandra")
            .notes(
                "Column types limited to int, varchar and boolean - no collections, UDTs, \
                 blobs, timestamps or numeric types beyond 32-bit int. No paging, batching, \
                 compression or server events. No storage: the handler answers every query; \
                 only prepared-statement metadata is held, per connection and capped.",
            )
            .max_inbound_bytes(crate::server::cassandra::MAX_FRAME_BODY_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "Cassandra/CQL database server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a Cassandra/CQL database server on port 9042"
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic: answer every CQL query with a single-column "OK"
        // rowset, no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
if data["event_type_id"] == "cassandra_query":
    actions = [{"type": "cassandra_result_rows",
                "columns": [{"name": "result", "type": "varchar"}],
                "rows": [["OK"]]}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: LLM handles all Cassandra responses intelligently
            json!({
                "type": "open_server",
                "port": 9042,
                "base_stack": "cassandra",
                "instruction": "Cassandra/CQL database server answering queries"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_server",
                "port": 9042,
                "base_stack": "cassandra",
                "event_handlers": [{
                    "event_pattern": "cassandra_query",
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
                "port": 9042,
                "base_stack": "cassandra",
                "event_handlers": [{
                    "event_pattern": "cassandra_query",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "cassandra_result_rows",
                            "columns": [{"name": "result", "type": "varchar"}],
                            "rows": [["OK"]]
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for CassandraProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::cassandra::CassandraServer;

            CassandraServer::spawn_with_llm_actions(
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
            "cassandra_ready" => self.execute_cassandra_ready(),
            "cassandra_authenticate" => self.execute_cassandra_authenticate(action),
            "cassandra_supported" => self.execute_cassandra_supported(action),
            "cassandra_result_rows" => self.execute_cassandra_result_rows(action),
            "cassandra_prepared" => self.execute_cassandra_prepared(action),
            "cassandra_auth_success" => self.execute_cassandra_auth_success(),
            "cassandra_error" => self.execute_cassandra_error(action),
            // `close_connection` is an alias, deliberately not advertised alongside
            // `close_this_connection`: the dashboard's "[ disconnect this peer ]" injects a
            // bare `{"type": "close_connection"}` through the peer handle whatever a protocol
            // calls its own close verb, so without the alias that button answers "Unknown
            // Cassandra action". Advertising it would put a second name for one thing in the
            // model's tool list.
            "close_this_connection" | "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown Cassandra action: {}", action_type)),
        }
    }
}

impl CassandraProtocol {
    fn execute_cassandra_ready(&self) -> Result<ActionResult> {
        debug!("Cassandra READY response");
        let _ = self.status_tx.send(format!("[DEBUG] Cassandra → READY"));

        Ok(ActionResult::Custom {
            name: "cassandra_ready".to_string(),
            data: json!({}),
        })
    }

    fn execute_cassandra_authenticate(&self, action: serde_json::Value) -> Result<ActionResult> {
        let authenticator = action
            .get("authenticator")
            .and_then(|v| v.as_str())
            .unwrap_or("org.apache.cassandra.auth.PasswordAuthenticator");

        debug!("Cassandra AUTHENTICATE challenge: {}", authenticator);
        let _ = self.status_tx.send(format!(
            "[DEBUG] Cassandra → AUTHENTICATE ({})",
            authenticator
        ));

        Ok(ActionResult::Custom {
            name: "cassandra_authenticate".to_string(),
            data: json!({ "authenticator": authenticator }),
        })
    }

    fn execute_cassandra_supported(&self, action: serde_json::Value) -> Result<ActionResult> {
        // A driver reads CQL_VERSION out of SUPPORTED to pick what to send in STARTUP. An
        // empty multimap tells it the server supports nothing, so answer with the documented
        // defaults when the handler gives none rather than shipping an empty frame.
        let options = action
            .get("options")
            .and_then(|v| v.as_object())
            .cloned()
            .filter(|o| !o.is_empty())
            .unwrap_or_else(|| {
                json!({
                    "CQL_VERSION": ["3.0.0"],
                    "COMPRESSION": [],
                    "PROTOCOL_VERSIONS": ["4/v4"],
                })
                .as_object()
                .cloned()
                .unwrap_or_default()
            });

        debug!(
            "Cassandra SUPPORTED response with {} option(s)",
            options.len()
        );
        let _ = self
            .status_tx
            .send("[DEBUG] Cassandra → SUPPORTED".to_string());

        Ok(ActionResult::Custom {
            name: "cassandra_supported".to_string(),
            data: json!({ "options": options }),
        })
    }

    fn execute_cassandra_result_rows(&self, action: serde_json::Value) -> Result<ActionResult> {
        let columns = action
            .get("columns")
            .and_then(|v| v.as_array())
            .context("Missing 'columns' array")?;

        let rows = action
            .get("rows")
            .and_then(|v| v.as_array())
            .context("Missing 'rows' array")?;

        debug!(
            "Cassandra result rows: {} columns, {} rows",
            columns.len(),
            rows.len()
        );

        let _ = self.status_tx.send(format!(
            "[DEBUG] Cassandra → Result set: {} columns, {} rows",
            columns.len(),
            rows.len()
        ));

        Ok(ActionResult::Custom {
            name: "cassandra_result_rows".to_string(),
            data: json!({
                "columns": columns,
                "rows": rows
            }),
        })
    }

    fn execute_cassandra_prepared(&self, action: serde_json::Value) -> Result<ActionResult> {
        let columns = action
            .get("columns")
            .and_then(|v| v.as_array())
            .context("Missing 'columns' array")?;

        let params = action.get("params").and_then(|v| v.as_array()).cloned();

        debug!(
            "Cassandra prepared statement: {} result columns, {} params",
            columns.len(),
            params.as_ref().map(|p| p.len()).unwrap_or(0)
        );

        let _ = self.status_tx.send(format!(
            "[DEBUG] Cassandra → Prepared statement ({} columns, {} params)",
            columns.len(),
            params.as_ref().map(|p| p.len()).unwrap_or(0)
        ));

        Ok(ActionResult::Custom {
            name: "cassandra_prepared".to_string(),
            data: json!({
                "columns": columns,
                "params": params
            }),
        })
    }

    fn execute_cassandra_auth_success(&self) -> Result<ActionResult> {
        debug!("Cassandra authentication successful");

        let _ = self
            .status_tx
            .send(format!("[DEBUG] Cassandra → AUTH_SUCCESS"));

        Ok(ActionResult::Custom {
            name: "cassandra_auth_success".to_string(),
            data: json!({}),
        })
    }

    fn execute_cassandra_error(&self, action: serde_json::Value) -> Result<ActionResult> {
        // Range-check before narrowing. `as u32` wraps, and 0x1_0000_1000 becomes 0x1000 —
        // the driver is told the cluster was Unavailable when the model said something else
        // entirely. The wire field is a 4-byte int, so that is the honest bound.
        let error_code = action
            .get("error_code")
            .and_then(|v| v.as_u64())
            .unwrap_or(0x0000);
        if error_code > u32::MAX as u64 {
            return Err(anyhow::anyhow!(
                "error_code {error_code} does not fit the 4-byte code a Cassandra ERROR frame \
                 carries. Native protocol v4 §9: 0x0000 server error, 0x000A protocol error, \
                 0x0100 bad credentials, 0x1000 unavailable, 0x1001 overloaded, 0x2000 syntax \
                 error, 0x2100 unauthorized, 0x2200 invalid, 0x2400 already exists."
            ));
        }
        let error_code = error_code as u32;

        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown error");

        debug!(
            "Cassandra error response: 0x{:04X} - {}",
            error_code, message
        );

        let _ = self.status_tx.send(format!(
            "[DEBUG] Cassandra ✗ Error 0x{:04X}: {}",
            error_code, message
        ));

        Ok(ActionResult::Custom {
            name: "cassandra_error".to_string(),
            data: json!({
                "error_code": error_code,
                "message": message
            }),
        })
    }
}

// Action definitions

fn cassandra_authenticate_action() -> ActionDefinition {
    ActionDefinition {
        name: "cassandra_authenticate".to_string(),
        description: "Demand authentication instead of sending READY. The client answers with \
                      an AUTH_RESPONSE, which raises cassandra_auth. Without this action the \
                      client never authenticates and cassandra_auth never fires."
            .to_string(),
        parameters: vec![Parameter {
            name: "authenticator".to_string(),
            type_hint: "string".to_string(),
            description: "Java class name of the authenticator to advertise. Drivers only \
                          understand org.apache.cassandra.auth.PasswordAuthenticator (SASL \
                          PLAIN), which is the default."
                .to_string(),
            required: false,
        }],
        example: json!({
            "type": "cassandra_authenticate",
            "authenticator": "org.apache.cassandra.auth.PasswordAuthenticator"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Cassandra AUTHENTICATE")
                .with_debug("Cassandra cassandra_authenticate: {authenticator}"),
        ),
    }
}

fn cassandra_ready_action() -> ActionDefinition {
    ActionDefinition {
        name: "cassandra_ready".to_string(),
        description: "Send READY response after successful STARTUP".to_string(),
        parameters: vec![],
        example: json!({"type": "cassandra_ready"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Cassandra READY")
                .with_debug("Cassandra cassandra_ready"),
        ),
    }
}

fn cassandra_supported_action() -> ActionDefinition {
    ActionDefinition {
        name: "cassandra_supported".to_string(),
        description: "Send SUPPORTED response with server capabilities".to_string(),
        parameters: vec![Parameter {
            name: "options".to_string(),
            type_hint: "object".to_string(),
            description: "Map of supported options (e.g., CQL_VERSION, COMPRESSION)".to_string(),
            required: false,
        }],
        example: json!({
            "type": "cassandra_supported",
            "options": {
                "CQL_VERSION": ["3.0.0"],
                "COMPRESSION": []
            }
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Cassandra SUPPORTED")
                .with_debug("Cassandra cassandra_supported"),
        ),
    }
}

fn cassandra_result_rows_action() -> ActionDefinition {
    ActionDefinition {
        name: "cassandra_result_rows".to_string(),
        description: "Send query result with rows of data".to_string(),
        parameters: vec![
            Parameter {
                name: "columns".to_string(),
                type_hint: "array".to_string(),
                description: "Column definitions with name and type".to_string(),
                required: true,
            },
            Parameter {
                name: "rows".to_string(),
                type_hint: "array".to_string(),
                description: "Array of row arrays".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "cassandra_result_rows",
            "columns": [
                {"name": "id", "type": "int"},
                {"name": "name", "type": "varchar"}
            ],
            "rows": [[1, "Alice"], [2, "Bob"]]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Cassandra {columns_len} cols, {rows_len} rows")
                .with_debug("Cassandra result_rows: {columns_len} columns, {rows_len} rows"),
        ),
    }
}

fn cassandra_prepared_action() -> ActionDefinition {
    ActionDefinition {
        name: "cassandra_prepared".to_string(),
        description: "Send prepared statement response with parameter and result column metadata"
            .to_string(),
        parameters: vec![
            Parameter {
                name: "columns".to_string(),
                type_hint: "array".to_string(),
                description:
                    "Column definitions for the result set that the prepared query will return"
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "params".to_string(),
                type_hint: "array".to_string(),
                description:
                    "Parameter type definitions for bind markers (optional, defaults to varchar)"
                        .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "cassandra_prepared",
            "params": [
                {"type": "int"}
            ],
            "columns": [
                {"name": "id", "type": "int"},
                {"name": "name", "type": "varchar"}
            ]
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Cassandra PREPARED ({columns_len} cols)")
                .with_debug("Cassandra cassandra_prepared: {columns_len} columns"),
        ),
    }
}

fn cassandra_auth_success_action() -> ActionDefinition {
    ActionDefinition {
        name: "cassandra_auth_success".to_string(),
        description: "Accept authentication and send AUTH_SUCCESS".to_string(),
        parameters: vec![],
        example: json!({"type": "cassandra_auth_success"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Cassandra AUTH_SUCCESS")
                .with_debug("Cassandra cassandra_auth_success"),
        ),
    }
}

fn cassandra_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "cassandra_error".to_string(),
        description: "Send error response to the client".to_string(),
        parameters: vec![
            Parameter {
                name: "error_code".to_string(),
                type_hint: "number".to_string(),
                description: "Cassandra error code (e.g., 0x2200 for syntax error)".to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Error message".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "cassandra_error",
            "error_code": 0x2200,
            "message": "Syntax error in CQL query"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Cassandra ERROR 0x{error_code:04X}: {message}")
                .with_debug("Cassandra cassandra_error: 0x{error_code:04X}"),
        ),
    }
}

fn close_this_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "close_this_connection".to_string(),
        description: "Close the current Cassandra connection".to_string(),
        parameters: vec![],
        example: json!({"type": "close_this_connection"}),
        log_template: Some(
            LogTemplate::new()
                .with_info("Cassandra connection closed")
                .with_debug("Cassandra close_this_connection"),
        ),
    }
}

// Event types

pub static CASSANDRA_STARTUP_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "cassandra_startup",
        "Client sends STARTUP frame with protocol version and options",
        json!({
            "type": "cassandra_ready"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "protocol_version".to_string(),
            type_hint: "number".to_string(),
            description: "CQL protocol version".to_string(),
            required: true,
        },
        Parameter {
            name: "options".to_string(),
            type_hint: "object".to_string(),
            description: "Startup options (e.g., CQL_VERSION)".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        cassandra_ready_action(),
        cassandra_authenticate_action(),
        cassandra_error_action(),
    ])
});

pub static CASSANDRA_OPTIONS_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "cassandra_options",
        "Client requests supported protocol options",
        json!({
            "type": "cassandra_supported",
            "options": {
                "CQL_VERSION": ["3.0.0"],
                "COMPRESSION": []
            }
        }),
    )
    .with_actions(vec![cassandra_supported_action(), cassandra_error_action()])
});

pub static CASSANDRA_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "cassandra_query",
        "Client sends CQL query to execute",
        // This is rendered verbatim into the prompt as "how to answer this event". It used to
        // be {"type": "placeholder", "event_id": "cassandra_query"}, which is not an action
        // and is rejected by execute_action.
        json!({
            "type": "cassandra_result_rows",
            "columns": [
                {"name": "id", "type": "int"},
                {"name": "name", "type": "varchar"}
            ],
            "rows": [[1, "Alice"], [2, "Bob"]]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "query".to_string(),
            type_hint: "string".to_string(),
            description: "The CQL query string".to_string(),
            required: true,
        },
        Parameter {
            name: "consistency".to_string(),
            type_hint: "string".to_string(),
            // This was reported as the literal "ONE" for every query regardless of what the
            // client asked for. It is now the level read off the frame; `UNKNOWN` means the
            // code was outside the defined set, never a guess.
            description: "Consistency level the client requested, read from the frame: ANY, \
                          ONE, TWO, THREE, QUORUM, ALL, LOCAL_QUORUM, EACH_QUORUM, SERIAL, \
                          LOCAL_SERIAL, LOCAL_ONE, or UNKNOWN if the code is not one of those"
                .to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        cassandra_result_rows_action(),
        cassandra_error_action(),
        close_this_connection_action(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Cassandra {client_ip}: {preview(query,80)}")
            .with_debug("Cassandra query from {client_ip}:{client_port}")
            .with_trace("Cassandra: {json_pretty(.)}"),
    )
});

pub static CASSANDRA_PREPARE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "cassandra_prepare",
        "Client sends PREPARE frame to prepare a parameterized query",
        json!({
            "type": "cassandra_prepared",
            "columns": [
                {"name": "id", "type": "int"},
                {"name": "name", "type": "varchar"}
            ],
            "params": [{"type": "int"}]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "query".to_string(),
            type_hint: "string".to_string(),
            description: "The parameterized CQL query with ? placeholders".to_string(),
            required: true,
        },
        Parameter {
            name: "statement_id".to_string(),
            type_hint: "string".to_string(),
            description: "Generated statement ID (hex encoded)".to_string(),
            required: true,
        },
        Parameter {
            name: "param_count".to_string(),
            type_hint: "number".to_string(),
            description: "Number of parameters in the query".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![cassandra_prepared_action(), cassandra_error_action()])
});

pub static CASSANDRA_EXECUTE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "cassandra_execute",
        "Client sends EXECUTE frame to execute a prepared statement with parameters",
        json!({
            "type": "cassandra_result_rows",
            "columns": [
                {"name": "id", "type": "int"},
                {"name": "name", "type": "varchar"}
            ],
            "rows": [[1, "Alice"], [2, "Bob"]]
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "query".to_string(),
            type_hint: "string".to_string(),
            description: "The original prepared query".to_string(),
            required: true,
        },
        Parameter {
            name: "statement_id".to_string(),
            type_hint: "string".to_string(),
            description: "Statement ID (hex encoded)".to_string(),
            required: true,
        },
        Parameter {
            name: "parameters".to_string(),
            type_hint: "array".to_string(),
            description: "Bound parameter values".to_string(),
            required: true,
        },
        Parameter {
            name: "consistency".to_string(),
            type_hint: "string".to_string(),
            description: "Consistency level the client requested, read from the frame: ANY, \
                          ONE, TWO, THREE, QUORUM, ALL, LOCAL_QUORUM, EACH_QUORUM, SERIAL, \
                          LOCAL_SERIAL, LOCAL_ONE, or UNKNOWN if the code is not one of those"
                .to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        cassandra_result_rows_action(),
        cassandra_error_action(),
    ])
});

pub static CASSANDRA_AUTH_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "cassandra_auth",
        "Client sends AUTH_RESPONSE with credentials (SASL PLAIN)",
        json!({
            "type": "cassandra_auth_success"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "username".to_string(),
            type_hint: "string".to_string(),
            description: "Username from SASL PLAIN authentication".to_string(),
            required: true,
        },
        Parameter {
            name: "password".to_string(),
            type_hint: "string".to_string(),
            description: "Password from SASL PLAIN authentication".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![
        cassandra_auth_success_action(),
        cassandra_error_action(),
        close_this_connection_action(),
    ])
});

pub fn get_cassandra_event_types() -> Vec<EventType> {
    vec![
        CASSANDRA_STARTUP_EVENT.clone(),
        CASSANDRA_OPTIONS_EVENT.clone(),
        CASSANDRA_QUERY_EVENT.clone(),
        CASSANDRA_PREPARE_EVENT.clone(),
        CASSANDRA_EXECUTE_EVENT.clone(),
        CASSANDRA_AUTH_EVENT.clone(),
    ]
}

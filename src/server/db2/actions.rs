//! IBM Db2 (DRDA) protocol actions implementation.
//!
//! The LLM plays the Db2 server: it decides whether a login is accepted and what
//! SQLCA a statement produces. **There is no storage** — no catalog, no tables, no
//! row store in Rust. The DRDA/DDM wire encoding lives in [`super::drda`]; this
//! module declares the events the model answers and the actions it answers with.

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

/// Db2 protocol action handler (stateless description; no storage).
pub struct Db2Protocol {
    _connection_id: ConnectionId,
    _app_state: Arc<AppState>,
    status_tx: mpsc::UnboundedSender<String>,
}

impl Db2Protocol {
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

impl Protocol for Db2Protocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        // Nothing to configure at spawn time — declaring an unread parameter is a
        // documented trap, so declare none.
        vec![]
    }

    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            db2_accept_connection_action(),
            db2_reject_connection_action(),
            db2_query_ok_action(),
            db2_query_error_action(),
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "Db2"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        get_db2_event_types()
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>DRDA>Db2"
    }

    fn keywords(&self) -> Vec<&'static str> {
        // Distinctive, multi-word keywords — no bare "db"/"sql"/"database".
        vec!["db2", "ibm db2", "drda"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .well_known_port(446)
            .implementation(
                "Hand-rolled DRDA/DDM codec (src/server/db2/drda.rs) against the public DRDA spec — \
                 no maintained Rust DRDA crate exists",
            )
            .llm_control("Login accept/reject decision, and the SQLCA (SQLCODE/SQLSTATE) for a statement")
            .e2e_testing(
                "tests/server/db2/real_client_test.rs: two independent drivers - Apache Derby \
                 10.17.1.0's JDBC client (through ij) and IBM's CLI driver (ibm_db 3.3.0) - log \
                 in, are refused when the model refuses, run statements and read back the \
                 model's row count and SQLSTATE; IBM's driver's default encrypted security \
                 mechanism is declined. tshark's drda dissector reads both conversations. \
                 Byte-literal tests of the codec beside it",
            )
            .notes(
                "Scope: the connection handshake (EXCSAT/ACCSEC/SECCHK/ACCRDB) and the \
                 EXCSQLIMM -> SQLCARD basic-query path (statement text extracted, model decides the \
                 SQLCA). NOT implemented: SELECT result-set retrieval (OPNQRY/QRYDSC/QRYDTA/FDOCA \
                 rows), PRPSQLSTT and prepared-statement parameter marshalling (refused with \
                 CMDNSPRM), message text in the SQLCA, and TLS. RDBCMM/RDBRLLBCK are acknowledged \
                 (there is no storage to commit). Experimental: statements only, no result \
                 sets. Fail-closed: an LLM outage during login is a refusal (SECCHKRM \
                 severity ERROR), never an accept.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "IBM Db2 database server (DRDA wire protocol: handshake + basic query)"
    }

    fn example_prompt(&self) -> &'static str {
        "Start an IBM Db2 server on port 50000 that accepts logins and answers statements"
    }

    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic: acknowledge every statement with a success SQLCA
        // (zero rows affected), no LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
if data["event_type_id"] == "db2_query":
    actions = [{"type": "db2_query_ok", "rows_affected": 0}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode
            json!({
                "type": "open_server",
                "port": 50000,
                "base_stack": "db2",
                "instruction": "IBM Db2 server: accept logins for user db2inst1 and answer statements"
            }),
            // Script mode
            json!({
                "type": "open_server",
                "port": 50000,
                "base_stack": "db2",
                "event_handlers": [{
                    "event_pattern": "db2_query",
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
                "port": 50000,
                "base_stack": "db2",
                "event_handlers": [{
                    "event_pattern": "db2_connect",
                    "handler": {
                        "type": "static",
                        "actions": [{"type": "db2_accept_connection"}]
                    }
                }]
            }),
        )
    }
}

impl Server for Db2Protocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::db2::Db2Server;
            Db2Server::spawn_with_llm_actions(
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
            "db2_accept_connection" => Ok(ActionResult::Custom {
                name: "db2_accept_connection".to_string(),
                data: json!({}),
            }),
            "db2_reject_connection" => self.execute_reject(action),
            "db2_query_ok" => self.execute_query_ok(action),
            "db2_query_error" => self.execute_query_error(action),
            // The dashboard's "[ disconnect this peer ]" injects this. The generic
            // peer-command task half-closes the write side on CloseConnection; the
            // reader's `read() == 0` path then runs the normal teardown.
            "close_connection" => Ok(ActionResult::CloseConnection),
            _ => Err(anyhow::anyhow!("Unknown Db2 action: {}", action_type)),
        }
    }
}

impl Db2Protocol {
    fn execute_reject(&self, action: serde_json::Value) -> Result<ActionResult> {
        let reason = action
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("authentication failed")
            .to_string();
        let sec_check_code = action
            .get("sec_check_code")
            .and_then(|v| v.as_str())
            .unwrap_or("password_invalid")
            .to_string();
        debug!("Db2 reject connection: {} ({})", reason, sec_check_code);
        let _ = self
            .status_tx
            .send(format!("[DEBUG] Db2 ✗ reject: {}", reason));
        Ok(ActionResult::Custom {
            name: "db2_reject_connection".to_string(),
            data: json!({ "reason": reason, "sec_check_code": sec_check_code }),
        })
    }

    fn execute_query_ok(&self, action: serde_json::Value) -> Result<ActionResult> {
        let rows_affected = action.get("rows_affected").and_then(|v| v.as_i64());
        let sqlcode = action.get("sqlcode").and_then(|v| v.as_i64()).unwrap_or(0);
        debug!(
            "Db2 query ok: sqlcode={}, rows={:?}",
            sqlcode, rows_affected
        );
        let _ = self.status_tx.send(format!(
            "[DEBUG] Db2 → OK sqlcode={} rows={:?}",
            sqlcode, rows_affected
        ));
        Ok(ActionResult::Custom {
            name: "db2_query_ok".to_string(),
            data: json!({ "rows_affected": rows_affected, "sqlcode": sqlcode }),
        })
    }

    fn execute_query_error(&self, action: serde_json::Value) -> Result<ActionResult> {
        let sqlcode = action
            .get("sqlcode")
            .and_then(|v| v.as_i64())
            .unwrap_or(-104);
        let sqlstate = action
            .get("sqlstate")
            .and_then(|v| v.as_str())
            .unwrap_or("42601")
            .to_string();
        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("SQL error")
            .to_string();
        debug!(
            "Db2 query error: sqlcode={}, sqlstate={}",
            sqlcode, sqlstate
        );
        let _ = self.status_tx.send(format!(
            "[DEBUG] Db2 ✗ SQL error sqlcode={} sqlstate={}",
            sqlcode, sqlstate
        ));
        Ok(ActionResult::Custom {
            name: "db2_query_error".to_string(),
            data: json!({ "sqlcode": sqlcode, "sqlstate": sqlstate, "message": message }),
        })
    }
}

// ============================================================================
// Action definitions
// ============================================================================

pub fn db2_accept_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "db2_accept_connection".to_string(),
        description:
            "Accept the client's login (the security check succeeds). Emit this only when \
            the credentials should be accepted; to refuse, use db2_reject_connection. Leaving the \
            db2_connect event unanswered is treated as a refusal."
                .to_string(),
        parameters: vec![],
        example: json!({ "type": "db2_accept_connection" }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Db2 login accepted")
                .with_debug("Db2 db2_accept_connection"),
        ),
    }
}

pub fn db2_reject_connection_action() -> ActionDefinition {
    ActionDefinition {
        name: "db2_reject_connection".to_string(),
        description: "Refuse the client's login. The server replies with a SECCHKRM (security \
            check reply message) at severity ERROR."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "reason".to_string(),
                type_hint: "string".to_string(),
                description: "Human-readable reason (for logs)".to_string(),
                required: false,
            },
            Parameter {
                name: "sec_check_code".to_string(),
                type_hint: "string".to_string(),
                description: "Which security-check failure to report: \"password_invalid\" \
                    (default), \"userid_unknown\", or \"userid_missing\"."
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "db2_reject_connection",
            "reason": "Invalid password",
            "sec_check_code": "password_invalid"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Db2 login rejected: {reason}")
                .with_debug("Db2 db2_reject_connection: {sec_check_code}"),
        ),
    }
}

pub fn db2_query_ok_action() -> ActionDefinition {
    ActionDefinition {
        name: "db2_query_ok".to_string(),
        description: "Report a successful statement. The server replies with an SQLCARD carrying \
            the SQLCA. With sqlcode 0 and no rows_affected the SQLCA is sent NULL (the normal \
            success reply); with rows_affected it carries that count in SQLERRD3, which a JDBC \
            driver reports as the update count. NOTE: row data is not returned — SELECT \
            result-set retrieval is not implemented; use this for INSERT/UPDATE/DELETE/DDL-style \
            statements."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "sqlcode".to_string(),
                type_hint: "number".to_string(),
                description: "SQLCODE to report (default 0 = success; e.g. 100 = no rows found)"
                    .to_string(),
                required: false,
            },
            Parameter {
                name: "rows_affected".to_string(),
                type_hint: "number".to_string(),
                description: "Rows the statement inserted, updated or deleted; sent in SQLERRD3 \
                    (with sqlcode 0)"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({ "type": "db2_query_ok", "sqlcode": 0, "rows_affected": 1 }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Db2 OK sqlcode={sqlcode}")
                .with_debug("Db2 db2_query_ok: sqlcode={sqlcode}, rows_affected={rows_affected}"),
        ),
    }
}

pub fn db2_query_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "db2_query_error".to_string(),
        description: "Report a statement failure. The server replies with an SQLCARD whose SQLCA \
            carries the SQLCODE and SQLSTATE you provide."
            .to_string(),
        parameters: vec![
            Parameter {
                name: "sqlcode".to_string(),
                type_hint: "number".to_string(),
                description:
                    "Negative SQLCODE, e.g. -204 (object not found), -104 (syntax error), \
                    -911 (deadlock/timeout)."
                        .to_string(),
                required: true,
            },
            Parameter {
                name: "sqlstate".to_string(),
                type_hint: "string".to_string(),
                description: "5-character SQLSTATE, e.g. \"42704\", \"42601\", \"40001\""
                    .to_string(),
                required: true,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Error message (logged; the SQLCA message text field is not encoded)"
                    .to_string(),
                required: false,
            },
        ],
        example: json!({
            "type": "db2_query_error",
            "sqlcode": -204,
            "sqlstate": "42704",
            "message": "DB2INST1.USERS is an undefined name"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> Db2 ERR sqlcode={sqlcode} sqlstate={sqlstate}")
                .with_debug("Db2 db2_query_error: sqlcode={sqlcode}, sqlstate={sqlstate}"),
        ),
    }
}

// ============================================================================
// Action constants (attached to events)
// ============================================================================

pub static DB2_ACCEPT_CONNECTION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(db2_accept_connection_action);
pub static DB2_REJECT_CONNECTION_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(db2_reject_connection_action);
pub static DB2_QUERY_OK_ACTION: LazyLock<ActionDefinition> = LazyLock::new(db2_query_ok_action);
pub static DB2_QUERY_ERROR_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(db2_query_error_action);

// ============================================================================
// Event types
// ============================================================================

/// Emitted after the client sends SECCHK (security check) with its credentials.
pub static DB2_CONNECT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "db2_connect",
        "Db2 client login (security check) received",
        json!({ "type": "db2_accept_connection" }),
    )
    .with_parameters(vec![
        Parameter {
            name: "user_id".to_string(),
            type_hint: "string".to_string(),
            description: "The user id the client is authenticating as (EBCDIC-decoded)".to_string(),
            required: false,
        },
        Parameter {
            name: "rdb_name".to_string(),
            type_hint: "string".to_string(),
            description: "The relational database (RDBNAM) the client wants to access".to_string(),
            required: false,
        },
        Parameter {
            name: "has_password".to_string(),
            type_hint: "boolean".to_string(),
            description: "True if a password was supplied in the security check".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        DB2_ACCEPT_CONNECTION_ACTION.clone(),
        DB2_REJECT_CONNECTION_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Db2 login: {user_id}@{rdb_name}")
            .with_debug("Db2 connect: user={user_id} rdb={rdb_name} has_password={has_password}"),
    )
});

/// Emitted when the client executes a statement (EXCSQLIMM).
pub static DB2_QUERY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "db2_query",
        "Db2 SQL statement received",
        json!({ "type": "db2_query_ok", "sqlcode": 0 }),
    )
    .with_parameters(vec![
        Parameter {
            name: "sql_text".to_string(),
            type_hint: "string".to_string(),
            description: "The SQL statement text, decoded from the requester's SQLSTT (UTF-8; bare EBCDIC is also read)".to_string(),
            required: true,
        },
        Parameter {
            name: "statement_type".to_string(),
            type_hint: "string".to_string(),
            description: "The DRDA command, e.g. \"execute_immediate\"".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        DB2_QUERY_OK_ACTION.clone(),
        DB2_QUERY_ERROR_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("Db2 query: {preview(sql_text,80)}")
            .with_debug("Db2 query: {sql_text}"),
    )
});

/// All Db2 event types.
pub fn get_db2_event_types() -> Vec<EventType> {
    vec![DB2_CONNECT_EVENT.clone(), DB2_QUERY_EVENT.clone()]
}

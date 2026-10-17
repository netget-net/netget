//! MSSQL client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// MSSQL client connected event
pub static MSSQL_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mssql_connected",
        "MSSQL client successfully connected to server",
        json!({
            "type": "execute_query",
            "query": "SELECT @@VERSION"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "remote_addr".to_string(),
        type_hint: "string".to_string(),
        description: "MSSQL server address".to_string(),
        required: true,
    }])
});

/// MSSQL client query result received event
pub static MSSQL_CLIENT_QUERY_RESULT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mssql_query_result",
        "Query result received from MSSQL server",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "columns".to_string(),
            type_hint: "array".to_string(),
            description: "Column definitions from result set".to_string(),
            required: true,
        },
        Parameter {
            name: "rows".to_string(),
            type_hint: "array".to_string(),
            description: "Rows from result set".to_string(),
            required: true,
        },
        Parameter {
            name: "rows_affected".to_string(),
            type_hint: "number".to_string(),
            description: "Number of rows affected (for non-SELECT queries)".to_string(),
            required: false,
        },
    ])
});

/// MSSQL client error event
pub static MSSQL_CLIENT_ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mssql_error",
        "Error received from MSSQL server",
        json!({"type": "placeholder", "event_id": "mssql_error"}),
    )
    .with_parameters(vec![
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
    ])
});

/// MSSQL client protocol action handler
pub struct MssqlClientProtocol;

impl MssqlClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for MssqlClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "execute_query".to_string(),
                description: "Execute an SQL query on the MSSQL server".to_string(),
                parameters: vec![Parameter {
                    name: "query".to_string(),
                    type_hint: "string".to_string(),
                    description: "SQL query to execute (e.g., SELECT * FROM users)".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "execute_query",
                    "query": "SELECT @@VERSION"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the MSSQL server".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
        ]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "execute_query".to_string(),
                description: "Execute an SQL query in response to received data".to_string(),
                parameters: vec![Parameter {
                    name: "query".to_string(),
                    type_hint: "string".to_string(),
                    description: "SQL query".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "execute_query",
                    "query": "INSERT INTO log VALUES ('event')"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more data without taking action".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "MSSQL"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            EventType::new(
                "mssql_connected",
                "Triggered when MSSQL client connects to server",
                json!({"type": "placeholder", "event_id": "mssql_connected"}),
            ),
            EventType::new(
                "mssql_query_result",
                "Triggered when MSSQL client receives query result",
                json!({"type": "placeholder", "event_id": "mssql_query_result"}),
            ),
            EventType::new(
                "mssql_error",
                "Triggered when MSSQL client receives error",
                json!({"type": "placeholder", "event_id": "mssql_error"}),
            ),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>TDS>MSSQL"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "mssql",
            "mssql client",
            "sql server client",
            "connect to mssql",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("tiberius TDS client library v0.12")
            .llm_control("Full control over SQL queries")
            .e2e_testing("Local MSSQL server or Docker container")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "MSSQL client for SQL Server database operations"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to MSSQL at localhost:1433 and execute SELECT @@VERSION"
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls MSSQL queries
            json!({
                "type": "open_client",
                "remote_addr": "localhost:1433;database=master;user=sa",
                "base_stack": "mssql",
                "instruction": "Query the database version and list all tables"
            }),
            // Script mode: Code-based SQL execution
            json!({
                "type": "open_client",
                "remote_addr": "localhost:1433;database=master;user=sa",
                "base_stack": "mssql",
                "event_handlers": [{
                    "event_pattern": "mssql_query_result",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<mssql_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed query responses
            json!({
                "type": "open_client",
                "remote_addr": "localhost:1433;database=master;user=sa",
                "base_stack": "mssql",
                "event_handlers": [
                    {
                        "event_pattern": "mssql_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "execute_query",
                                "query": "SELECT @@VERSION"
                            }]
                        }
                    },
                    {
                        "event_pattern": "mssql_query_result",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "disconnect"
                            }]
                        }
                    }
                ]
            }),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for MssqlClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::mssql::MssqlClient;
            MssqlClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
            )
            .await
        })
    }
    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .context("Missing 'type' field in action")?;

        match action_type {
            "execute_query" => {
                let query = action
                    .get("query")
                    .and_then(|v| v.as_str())
                    .context("Missing 'query' field")?
                    .to_string();

                Ok(ClientActionResult::Custom {
                    name: "mssql_query".to_string(),
                    data: json!({
                        "query": query,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown MSSQL client action: {}",
                action_type
            )),
        }
    }
}

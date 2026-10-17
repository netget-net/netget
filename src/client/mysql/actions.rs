//! MySQL client protocol actions implementation

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

/// MySQL client connected event
pub static MYSQL_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mysql_connected",
        "MySQL client successfully connected to server",
        json!({
            "type": "execute_query",
            "query": "SELECT * FROM users LIMIT 10"
        }),
    )
    .with_parameters(vec![Parameter {
        name: "remote_addr".to_string(),
        type_hint: "string".to_string(),
        description: "MySQL server address".to_string(),
        required: true,
    }])
});

/// MySQL client query result received event
pub static MYSQL_CLIENT_RESULT_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mysql_result_received",
        "Query result received from MySQL server",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "query".to_string(),
            type_hint: "string".to_string(),
            description: "The SQL query this result belongs to".to_string(),
            required: true,
        },
        Parameter {
            name: "result".to_string(),
            type_hint: "array".to_string(),
            description: "The rows returned, one object per row keyed by column name".to_string(),
            required: true,
        },
        Parameter {
            name: "row_count".to_string(),
            type_hint: "number".to_string(),
            description: "Number of rows returned".to_string(),
            required: true,
        },
        Parameter {
            name: "affected_rows".to_string(),
            type_hint: "number".to_string(),
            description: "Rows the server reports as affected (INSERT/UPDATE/DELETE); 0 for a \
                          SELECT"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "last_insert_id".to_string(),
            type_hint: "number".to_string(),
            description: "The AUTO_INCREMENT id the statement generated, when it generated one"
                .to_string(),
            required: false,
        },
    ])
});

/// MySQL client protocol action handler
pub struct MysqlClientProtocol;

impl MysqlClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for MysqlClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "execute_query".to_string(),
                description: "Execute a SQL query (SELECT, INSERT, UPDATE, DELETE, etc.)"
                    .to_string(),
                parameters: vec![Parameter {
                    name: "query".to_string(),
                    type_hint: "string".to_string(),
                    description: "SQL query to execute".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "execute_query",
                    "query": "SELECT * FROM users WHERE id = 1"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "begin_transaction".to_string(),
                description: "Begin a transaction".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "begin_transaction"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "commit_transaction".to_string(),
                description: "Commit the current transaction".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "commit_transaction"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "rollback_transaction".to_string(),
                description: "Rollback the current transaction".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "rollback_transaction"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the MySQL server".to_string(),
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
                description: "Execute a SQL query in response to received data".to_string(),
                parameters: vec![Parameter {
                    name: "query".to_string(),
                    type_hint: "string".to_string(),
                    description: "SQL query to execute".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "execute_query",
                    "query": "INSERT INTO logs (message) VALUES ('processed')"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more results without executing new queries".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }
    fn protocol_name(&self) -> &'static str {
        "MySQL"
    }
    /// The **statics**, not fresh `EventType::new(..)` copies.
    ///
    /// This used to build a second, different `EventType` for each id: no parameters, and a
    /// `{"type": "placeholder"}` example. Those are what the registry and the model-facing
    /// docs surface, while the emitted events carry the statics above — two sources of truth
    /// for the same event id, and they had already drifted.
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            MYSQL_CLIENT_CONNECTED_EVENT.clone(),
            MYSQL_CLIENT_RESULT_RECEIVED_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>MySQL"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "mysql",
            "mysql client",
            "connect to mysql",
            "sql",
            "database",
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .implementation(
                "mysql_async, one connection, text protocol. Each query's rows and the server's \
                 affected_rows / last_insert_id go back to the model as mysql_result_received, \
                 and the model's answer is executed in turn, bounded at four follow-ups",
            )
            .llm_control("Full control over SQL queries and transactions")
            .e2e_testing(
                "tests/client/mysql/real_server_test.rs, 6 LLM calls, against a real mysqld \
                 (--initialize-insecure, then mysqld on a loopback port) read back with the \
                 mysql CLI. The client connects with the database startup parameter; the model \
                 creates a table, inserts a row, selects it, and inserts a second row built \
                 from the SELECT's rows. The INSERT's result is matched on affected_rows 1 and \
                 last_insert_id 1, the SELECT's on the row it carries, and the CLI must read \
                 both rows back exactly. Not #[ignore]d; a missing mysqld or mysql fails the \
                 test rather than skipping it.",
            )
            .notes(
                "No TLS, and only a passwordless account is exercised against a real server. A \
                 query the server rejects marks the client Error and raises no event, so the \
                 model does not learn of the error. Text protocol only; no prepared \
                 statements.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "MySQL client for database operations"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to MySQL at localhost:3306 as root and query the users table"
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls MySQL queries
            json!({
                "type": "open_client",
                "remote_addr": "localhost:3306",
                "base_stack": "mysql",
                "instruction": "Query the users table and show all active users, then summarize the results"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "localhost:3306",
                "base_stack": "mysql",
                "event_handlers": [{
                    "event_pattern": "mysql_result_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<mysql_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed MySQL query on connect
            json!({
                "type": "open_client",
                "remote_addr": "localhost:3306",
                "base_stack": "mysql",
                "event_handlers": [
                    {
                        "event_pattern": "mysql_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "execute_query",
                                "query": "SELECT * FROM users LIMIT 10"
                            }]
                        }
                    },
                    {
                        "event_pattern": "mysql_result_received",
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

    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![
            crate::llm::actions::ParameterDefinition {
                name: "username".to_string(),
                type_hint: "string".to_string(),
                description: "MySQL username (default: root)".to_string(),
                required: false,
                example: json!("myuser"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "password".to_string(),
                type_hint: "string".to_string(),
                description: "MySQL password (default: empty)".to_string(),
                required: false,
                example: json!("mypassword"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "database".to_string(),
                type_hint: "string".to_string(),
                description: "Database name to connect to (default: none)".to_string(),
                required: false,
                example: json!("mydb"),
                default: None,
            },
        ]
    }
}

// Implement Client trait (client-specific functionality)
impl Client for MysqlClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::mysql::MysqlClient;
            MysqlClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                ctx.startup_params,
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
                    name: "mysql_query".to_string(),
                    data: json!({
                        "query": query,
                    }),
                })
            }
            "begin_transaction" => Ok(ClientActionResult::Custom {
                name: "mysql_query".to_string(),
                data: json!({
                    "query": "BEGIN",
                }),
            }),
            "commit_transaction" => Ok(ClientActionResult::Custom {
                name: "mysql_query".to_string(),
                data: json!({
                    "query": "COMMIT",
                }),
            }),
            "rollback_transaction" => Ok(ClientActionResult::Custom {
                name: "mysql_query".to_string(),
                data: json!({
                    "query": "ROLLBACK",
                }),
            }),
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown MySQL client action: {}",
                action_type
            )),
        }
    }
}

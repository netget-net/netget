//! MongoDB client protocol actions implementation

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

/// MongoDB client connected event
pub static MONGODB_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mongodb_connected",
        "MongoDB client successfully connected to server",
        json!({
            "type": "find_documents",
            "collection": "users",
            "filter": {}
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "MongoDB server address".to_string(),
            required: true,
        },
        Parameter {
            name: "database".to_string(),
            type_hint: "string".to_string(),
            description: "Connected database name".to_string(),
            required: true,
        },
    ])
});

/// MongoDB client result received event
pub static MONGODB_CLIENT_RESULT_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "mongodb_result_received",
        "Query result received from MongoDB server",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "result_type".to_string(),
            type_hint: "string".to_string(),
            description: "Type of result (find, insert, update, delete)".to_string(),
            required: true,
        },
        Parameter {
            name: "documents".to_string(),
            type_hint: "array".to_string(),
            description: "Result documents (for find queries)".to_string(),
            required: false,
        },
        Parameter {
            name: "count".to_string(),
            type_hint: "number".to_string(),
            description: "Count of affected documents (for insert/update/delete)".to_string(),
            required: false,
        },
    ])
});

/// MongoDB client protocol action handler
pub struct MongodbClientProtocol;

impl MongodbClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for MongodbClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "find_documents".to_string(),
                description: "Find documents matching a filter".to_string(),
                parameters: vec![
                    Parameter {
                        name: "collection".to_string(),
                        type_hint: "string".to_string(),
                        description: "Collection name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "filter".to_string(),
                        type_hint: "object".to_string(),
                        description: "MongoDB filter query (default: {})".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "projection".to_string(),
                        type_hint: "object".to_string(),
                        description: "Fields to include/exclude".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "limit".to_string(),
                        type_hint: "integer".to_string(),
                        description: "Maximum number of documents to return".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "find_documents",
                    "collection": "users",
                    "filter": {"age": {"$gte": 18}},
                    "limit": 10
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "insert_document".to_string(),
                description: "Insert a document into a collection".to_string(),
                parameters: vec![
                    Parameter {
                        name: "collection".to_string(),
                        type_hint: "string".to_string(),
                        description: "Collection name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "document".to_string(),
                        type_hint: "object".to_string(),
                        description: "Document to insert".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "insert_document",
                    "collection": "users",
                    "document": {"name": "Alice", "age": 30}
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "update_documents".to_string(),
                description: "Update documents matching a filter".to_string(),
                parameters: vec![
                    Parameter {
                        name: "collection".to_string(),
                        type_hint: "string".to_string(),
                        description: "Collection name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "filter".to_string(),
                        type_hint: "object".to_string(),
                        description: "MongoDB filter query".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "update".to_string(),
                        type_hint: "object".to_string(),
                        description: "Update operations (e.g., {\"$set\": {...}})".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "update_documents",
                    "collection": "users",
                    "filter": {"name": "Alice"},
                    "update": {"$set": {"age": 31}}
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "delete_documents".to_string(),
                description: "Delete documents matching a filter".to_string(),
                parameters: vec![
                    Parameter {
                        name: "collection".to_string(),
                        type_hint: "string".to_string(),
                        description: "Collection name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "filter".to_string(),
                        type_hint: "object".to_string(),
                        description: "MongoDB filter query".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "delete_documents",
                    "collection": "users",
                    "filter": {"age": {"$lt": 18}}
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the MongoDB server".to_string(),
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
                name: "find_documents".to_string(),
                description: "Find documents in response to received data".to_string(),
                parameters: vec![
                    Parameter {
                        name: "collection".to_string(),
                        type_hint: "string".to_string(),
                        description: "Collection name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "filter".to_string(),
                        type_hint: "object".to_string(),
                        description: "MongoDB filter query".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "find_documents",
                    "collection": "logs",
                    "filter": {}
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait for more results without executing new operations".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }

    fn protocol_name(&self) -> &'static str {
        "MongoDB"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            MONGODB_CLIENT_CONNECTED_EVENT.clone(),
            MONGODB_CLIENT_RESULT_RECEIVED_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>MongoDB"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec![
            "mongodb",
            "mongo",
            "mongodb client",
            "connect to mongodb",
            "nosql",
            "database",
        ]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Official mongodb v3.3 driver with async support")
            .llm_control("Full control over CRUD operations and queries")
            // Not a real MongoDB server, which is what this said. The e2e tests point the
            // driver at NetGet's *own* MongoDB server (feature `mongodb-server`), so the
            // official driver is the thing under test rather than the independent peer
            // corroborating it. No test has ever run this client against mongod.
            .e2e_testing("NetGet's own MongoDB server; never against a real mongod")
            .notes(
                "Follow-up chains are bounded by MAX_FOLLOWUP_DEPTH (4): every operation's \
                 result is reported to the model, and past the bound an action still runs but \
                 its result is not reported. One operation at a time - no aggregation \
                 pipeline, GridFS, change streams or transactions.",
            )
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "MongoDB client for NoSQL database operations"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to MongoDB at localhost:27017 database testdb and find all users"
    }

    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls MongoDB operations
            json!({
                "type": "open_client",
                "remote_addr": "localhost:27017",
                "base_stack": "mongodb",
                "instruction": "Find all users with age greater than 25 and summarize the results"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "localhost:27017",
                "base_stack": "mongodb",
                "event_handlers": [{
                    "event_pattern": "mongodb_result_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<mongodb_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed MongoDB query on connect
            json!({
                "type": "open_client",
                "remote_addr": "localhost:27017",
                "base_stack": "mongodb",
                "event_handlers": [
                    {
                        "event_pattern": "mongodb_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "find_documents",
                                "collection": "users",
                                "filter": {},
                                "limit": 10
                            }]
                        }
                    },
                    {
                        "event_pattern": "mongodb_result_received",
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
                name: "database".to_string(),
                type_hint: "string".to_string(),
                description: "MongoDB database name (default: admin)".to_string(),
                required: false,
                example: json!("testdb"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "username".to_string(),
                type_hint: "string".to_string(),
                description: "MongoDB username (if authentication required)".to_string(),
                required: false,
                example: json!("myuser"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "password".to_string(),
                type_hint: "string".to_string(),
                description: "MongoDB password (if authentication required)".to_string(),
                required: false,
                example: json!("mypassword"),
                default: None,
            },
        ]
    }
}

// Implement Client trait (client-specific functionality)
impl Client for MongodbClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            crate::client::mongodb::MongodbClient::connect_with_llm_actions(
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
            "find_documents" => {
                let collection = action
                    .get("collection")
                    .and_then(|v| v.as_str())
                    .context("Missing 'collection' field")?
                    .to_string();
                let filter = action.get("filter").cloned().unwrap_or(json!({}));
                let projection = action.get("projection").cloned();
                let limit = action.get("limit").and_then(|v| v.as_i64());

                Ok(ClientActionResult::Custom {
                    name: "mongodb_find".to_string(),
                    data: json!({
                        "collection": collection,
                        "filter": filter,
                        "projection": projection,
                        "limit": limit
                    }),
                })
            }
            "insert_document" => {
                let collection = action
                    .get("collection")
                    .and_then(|v| v.as_str())
                    .context("Missing 'collection' field")?
                    .to_string();
                let document = action
                    .get("document")
                    .context("Missing 'document' field")?
                    .clone();

                Ok(ClientActionResult::Custom {
                    name: "mongodb_insert".to_string(),
                    data: json!({
                        "collection": collection,
                        "document": document
                    }),
                })
            }
            "update_documents" => {
                let collection = action
                    .get("collection")
                    .and_then(|v| v.as_str())
                    .context("Missing 'collection' field")?
                    .to_string();
                let filter = action
                    .get("filter")
                    .context("Missing 'filter' field")?
                    .clone();
                let update = action
                    .get("update")
                    .context("Missing 'update' field")?
                    .clone();

                Ok(ClientActionResult::Custom {
                    name: "mongodb_update".to_string(),
                    data: json!({
                        "collection": collection,
                        "filter": filter,
                        "update": update
                    }),
                })
            }
            "delete_documents" => {
                let collection = action
                    .get("collection")
                    .and_then(|v| v.as_str())
                    .context("Missing 'collection' field")?
                    .to_string();
                let filter = action
                    .get("filter")
                    .context("Missing 'filter' field")?
                    .clone();

                Ok(ClientActionResult::Custom {
                    name: "mongodb_delete".to_string(),
                    data: json!({
                        "collection": collection,
                        "filter": filter
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            _ => Err(anyhow::anyhow!(
                "Unknown MongoDB client action: {}",
                action_type
            )),
        }
    }
}

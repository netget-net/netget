//! CouchDB client protocol actions implementation

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::Result;
use serde_json::json;
use std::sync::LazyLock;

/// CouchDB client connected event
pub static COUCHDB_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "couchdb_connected",
        "CouchDB client successfully connected to server",
        json!({"type": "list_databases"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "remote_addr".to_string(),
            type_hint: "string".to_string(),
            description: "CouchDB server address".to_string(),
            required: true,
        },
        Parameter {
            name: "server_info".to_string(),
            type_hint: "object".to_string(),
            description: "Server welcome information (version, etc.)".to_string(),
            required: false,
        },
    ])
});

/// CouchDB client response received event
pub static COUCHDB_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "couchdb_response_received",
        "Response received from CouchDB server",
        json!({"type": "get_document", "database": "mydb", "doc_id": "user1"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "The operation that was performed".to_string(),
            required: true,
        },
        Parameter {
            name: "success".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether the operation succeeded".to_string(),
            required: true,
        },
        Parameter {
            name: "data".to_string(),
            type_hint: "object".to_string(),
            description: "Response data from the operation".to_string(),
            required: false,
        },
        Parameter {
            name: "error".to_string(),
            type_hint: "string".to_string(),
            description: "Error message if operation failed".to_string(),
            required: false,
        },
    ])
});

/// CouchDB client conflict event
pub static COUCHDB_CLIENT_CONFLICT_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "couchdb_conflict",
        "Document update conflict detected (revision mismatch)",
        json!({"type": "get_document", "database": "mydb", "doc_id": "user1"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "database".to_string(),
            type_hint: "string".to_string(),
            description: "Database name".to_string(),
            required: true,
        },
        Parameter {
            name: "doc_id".to_string(),
            type_hint: "string".to_string(),
            description: "Document ID".to_string(),
            required: true,
        },
        Parameter {
            name: "expected_rev".to_string(),
            type_hint: "string".to_string(),
            description: "The revision that was expected".to_string(),
            required: false,
        },
    ])
});

/// CouchDB client change detected event (from changes feed)
pub static COUCHDB_CLIENT_CHANGE_DETECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "couchdb_change_detected",
        "Document change detected in changes feed",
        json!({"type": "get_document", "database": "mydb", "doc_id": "user1"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "database".to_string(),
            type_hint: "string".to_string(),
            description: "Database name".to_string(),
            required: true,
        },
        Parameter {
            name: "seq".to_string(),
            type_hint: "string".to_string(),
            description: "Sequence number".to_string(),
            required: true,
        },
        Parameter {
            name: "doc_id".to_string(),
            type_hint: "string".to_string(),
            description: "Changed document ID".to_string(),
            required: true,
        },
        Parameter {
            name: "changes".to_string(),
            type_hint: "array".to_string(),
            description: "Array of revision changes".to_string(),
            required: true,
        },
        Parameter {
            name: "deleted".to_string(),
            type_hint: "boolean".to_string(),
            description: "Whether the document was deleted".to_string(),
            required: false,
        },
    ])
});

/// CouchDB client protocol action handler
pub struct CouchDbClientProtocol;

impl CouchDbClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for CouchDbClientProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        vec![
            ActionDefinition {
                name: "create_database".to_string(),
                description: "Create a new database".to_string(),
                parameters: vec![Parameter {
                    name: "database".to_string(),
                    type_hint: "string".to_string(),
                    description: "Database name".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "create_database",
                    "database": "mydb"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "delete_database".to_string(),
                description: "Delete a database".to_string(),
                parameters: vec![Parameter {
                    name: "database".to_string(),
                    type_hint: "string".to_string(),
                    description: "Database name".to_string(),
                    required: true,
                }],
                example: json!({
                    "type": "delete_database",
                    "database": "mydb"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "list_databases".to_string(),
                description: "List all databases".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "list_databases"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "create_document".to_string(),
                description: "Create a new document".to_string(),
                parameters: vec![
                    Parameter {
                        name: "database".to_string(),
                        type_hint: "string".to_string(),
                        description: "Database name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "doc_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Document ID (optional, auto-generated if not provided)"
                            .to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "document".to_string(),
                        type_hint: "object".to_string(),
                        description: "Document data as JSON object".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "create_document",
                    "database": "mydb",
                    "doc_id": "user1",
                    "document": {"name": "Alice", "age": 30}
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "get_document".to_string(),
                description: "Retrieve a document".to_string(),
                parameters: vec![
                    Parameter {
                        name: "database".to_string(),
                        type_hint: "string".to_string(),
                        description: "Database name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "doc_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Document ID".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "get_document",
                    "database": "mydb",
                    "doc_id": "user1"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "update_document".to_string(),
                description: "Update an existing document (requires current revision)".to_string(),
                parameters: vec![
                    Parameter {
                        name: "database".to_string(),
                        type_hint: "string".to_string(),
                        description: "Database name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "doc_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Document ID".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "document".to_string(),
                        type_hint: "object".to_string(),
                        description: "Updated document data (must include _rev)".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "update_document",
                    "database": "mydb",
                    "doc_id": "user1",
                    "document": {"_rev": "1-abc", "name": "Alice", "age": 31}
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "delete_document".to_string(),
                description: "Delete a document (requires current revision)".to_string(),
                parameters: vec![
                    Parameter {
                        name: "database".to_string(),
                        type_hint: "string".to_string(),
                        description: "Database name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "doc_id".to_string(),
                        type_hint: "string".to_string(),
                        description: "Document ID".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "rev".to_string(),
                        type_hint: "string".to_string(),
                        description: "Current document revision".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "delete_document",
                    "database": "mydb",
                    "doc_id": "user1",
                    "rev": "2-abc"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "bulk_docs".to_string(),
                description: "Perform bulk document operations".to_string(),
                parameters: vec![
                    Parameter {
                        name: "database".to_string(),
                        type_hint: "string".to_string(),
                        description: "Database name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "docs".to_string(),
                        type_hint: "array".to_string(),
                        description: "Array of documents to create/update".to_string(),
                        required: true,
                    },
                ],
                example: json!({
                    "type": "bulk_docs",
                    "database": "mydb",
                    "docs": [
                        {"_id": "doc1", "name": "Alice"},
                        {"_id": "doc2", "name": "Bob"}
                    ]
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "list_documents".to_string(),
                description: "List all documents in a database".to_string(),
                parameters: vec![
                    Parameter {
                        name: "database".to_string(),
                        type_hint: "string".to_string(),
                        description: "Database name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "include_docs".to_string(),
                        type_hint: "boolean".to_string(),
                        description: "Whether to include full document content".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "list_documents",
                    "database": "mydb",
                    "include_docs": false
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "query_view".to_string(),
                description: "Query a MapReduce view".to_string(),
                parameters: vec![
                    Parameter {
                        name: "database".to_string(),
                        type_hint: "string".to_string(),
                        description: "Database name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "design_doc".to_string(),
                        type_hint: "string".to_string(),
                        description: "Design document name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "view_name".to_string(),
                        type_hint: "string".to_string(),
                        description: "View name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "params".to_string(),
                        type_hint: "object".to_string(),
                        description: "Query parameters (key, limit, skip, etc.)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "query_view",
                    "database": "mydb",
                    "design_doc": "users",
                    "view_name": "by_age",
                    "params": {"limit": 10}
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "watch_changes".to_string(),
                description: "Start watching changes feed".to_string(),
                parameters: vec![
                    Parameter {
                        name: "database".to_string(),
                        type_hint: "string".to_string(),
                        description: "Database name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "since".to_string(),
                        type_hint: "string".to_string(),
                        description: "Start sequence (or 'now')".to_string(),
                        required: false,
                    },
                    Parameter {
                        name: "feed".to_string(),
                        type_hint: "string".to_string(),
                        description: "Feed type: normal, longpoll, or continuous".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "watch_changes",
                    "database": "mydb",
                    "since": "now",
                    "feed": "longpoll"
                }),
                log_template: None,
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the CouchDB server".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: None,
            },
            // Declared, not just accepted. The executor took any name at all, so this appeared
            // to work while being advertised nowhere - the model could only reach it by
            // guessing, and every other guess was swallowed just as silently.
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Do nothing and wait for the next response. Correct when the \
                    previous operation needs no follow-up."
                    .to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: None,
            },
        ]
    }

    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        // Sync actions are same as async for CouchDB client (response-driven)
        self.get_async_actions(&AppState::new())
    }

    fn protocol_name(&self) -> &'static str {
        "CouchDB"
    }

    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            COUCHDB_CLIENT_CONNECTED_EVENT.clone(),
            COUCHDB_CLIENT_RESPONSE_RECEIVED_EVENT.clone(),
            COUCHDB_CLIENT_CONFLICT_EVENT.clone(),
            COUCHDB_CLIENT_CHANGE_DETECTED_EVENT.clone(),
        ]
    }

    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>COUCHDB"
    }

    fn keywords(&self) -> Vec<&'static str> {
        vec!["couchdb client", "connect to couchdb", "couchdb"]
    }

    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("couch_rs library with LLM action control")
            .llm_control("Full control over CouchDB operations")
            .e2e_testing("NetGet CouchDB server")
            .history(crate::protocol::metadata::HistoryMode::Last(
                crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
            ))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }

    fn description(&self) -> &'static str {
        "CouchDB client for document database operations"
    }

    fn example_prompt(&self) -> &'static str {
        "Connect to CouchDB at localhost:5984 and create a database called 'myapp'"
    }

    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        StartupExamples::new(
            // LLM mode: LLM controls CouchDB operations
            json!({
                "type": "open_client",
                "remote_addr": "localhost:5984",
                "base_stack": "couchdb",
                "instruction": "List all databases and then get documents from the 'users' database"
            }),
            // Script mode: Code-based deterministic responses
            json!({
                "type": "open_client",
                "remote_addr": "localhost:5984",
                "base_stack": "couchdb",
                "event_handlers": [{
                    "event_pattern": "couchdb_response_received",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "<couchdb_client_handler>"
                    }
                }]
            }),
            // Static mode: Fixed CouchDB list databases on connect
            json!({
                "type": "open_client",
                "remote_addr": "localhost:5984",
                "base_stack": "couchdb",
                "event_handlers": [
                    {
                        "event_pattern": "couchdb_connected",
                        "handler": {
                            "type": "static",
                            "actions": [{
                                "type": "list_databases"
                            }]
                        }
                    },
                    {
                        "event_pattern": "couchdb_response_received",
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
                description: "CouchDB username (for basic auth)".to_string(),
                required: false,
                example: json!("admin"),
                default: None,
            },
            crate::llm::actions::ParameterDefinition {
                name: "password".to_string(),
                type_hint: "string".to_string(),
                description: "CouchDB password (for basic auth)".to_string(),
                required: false,
                example: json!("password"),
                default: None,
            },
        ]
    }
}

// Implement Client trait (client-specific functionality)
impl Client for CouchDbClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::couchdb::CouchDbClient;

            let username = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("username"))
                .transpose()?
                .flatten();

            let password = ctx
                .startup_params
                .as_ref()
                .map(|p| p.get_optional_string("password"))
                .transpose()?
                .flatten();

            CouchDbClient::connect_with_llm_actions(
                ctx.remote_addr,
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.client_id,
                username,
                password,
            )
            .await
        })
    }

    fn execute_action(&self, action: serde_json::Value) -> Result<ClientActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing action type"))?;

        // Execution happens in the read loop in mod.rs, which dispatches on this name - so an
        // unrecognised one is passed on and quietly ignored there. Validating here instead
        // means a typo, an action from another protocol, or a common action this client cannot
        // run is reported to the model, which then gets a chance to correct it. Returning Ok
        // for everything also stopped the repair loop from ever firing.
        const COUCHDB_CLIENT_ACTIONS: &[&str] = &[
            "create_database",
            "delete_database",
            "list_databases",
            "create_document",
            "get_document",
            "update_document",
            "delete_document",
            "list_documents",
            "bulk_docs",
            "query_view",
            "watch_changes",
            "disconnect",
            "wait_for_more",
        ];

        if !COUCHDB_CLIENT_ACTIONS.contains(&action_type) {
            return Err(anyhow::anyhow!(
                "Unknown CouchDB client action '{}'. Valid actions: {}",
                action_type,
                COUCHDB_CLIENT_ACTIONS.join(", ")
            ));
        }

        Ok(ClientActionResult::Custom {
            name: action_type.to_string(),
            data: action,
        })
    }
}

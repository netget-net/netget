//! DynamoDB protocol actions and event types
//!
//! Defines the actions the LLM can take in response to DynamoDB API requests.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::LazyLock;

/// DynamoDB protocol handler
pub struct DynamoProtocol {
    // Could store connection state here if needed
}

impl DynamoProtocol {
    pub fn new() -> Self {
        Self {}
    }
}

/// DynamoDB request event - triggered when a DynamoDB API request is received
pub static DYNAMO_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "dynamo_request",
        "DynamoDB API request received",
        json!({"type": "placeholder", "event_id": "dynamo_request"}),
    )
    .with_parameters(vec![
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "DynamoDB operation (GetItem, PutItem, Query, etc.)".to_string(),
            required: true,
        },
        Parameter {
            name: "table_name".to_string(),
            type_hint: "string".to_string(),
            description: "Target table name (if available)".to_string(),
            required: false,
        },
        Parameter {
            name: "request_body".to_string(),
            type_hint: "string".to_string(),
            description: "JSON request body".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![send_dynamo_response_action()])
    .with_log_template(
        LogTemplate::new()
            .with_info("DynamoDB {operation}")
            .with_debug("DynamoDB {operation} on {table_name}")
            .with_trace("DynamoDB: {json_pretty(.)}"),
    )
});

fn send_dynamo_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_dynamo_response".to_string(),
        description: "Send DynamoDB JSON response with HTTP status code".to_string(),
        parameters: vec![
            Parameter {
                name: "status_code".to_string(),
                type_hint: "number".to_string(),
                description: "HTTP status code (200, 400, 500, etc.)".to_string(),
                required: true,
            },
            Parameter {
                name: "body".to_string(),
                type_hint: "string".to_string(),
                description: "JSON response body".to_string(),
                required: true,
            },
        ],
        example: serde_json::json!({
            "type": "send_dynamo_response",
            "status_code": 200,
            "body": "{\"Item\": {\"id\": {\"S\": \"user-123\"}, \"name\": {\"S\": \"Alice\"}}}"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> DynamoDB response (HTTP {status_code})")
                .with_debug("DynamoDB send_dynamo_response: status={status_code}"),
        ),
    }
}

/// Read and validate the model-supplied `status_code`.
///
/// The old `as u64 as u16` cast wrapped silently, and out-of-range values reached
/// `Response::builder().status()` where an `.unwrap()` turned them into a panic that
/// killed the connection task. Reject them here, where the message reaches the model.
fn parse_status_code(action: &Value) -> Result<u16> {
    let raw = action
        .get("status_code")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid status_code: expected a number"))?;

    if !(100..=599).contains(&raw) {
        return Err(anyhow::anyhow!(
            "Invalid status_code {raw}: must be an HTTP status between 100 and 599. \
             DynamoDB uses 200 for success and 400 with an \
             {{\"__type\": ..., \"message\": ...}} body for client errors."
        ));
    }

    Ok(raw as u16)
}

pub fn get_dynamo_event_types() -> Vec<EventType> {
    vec![DYNAMO_REQUEST_EVENT.clone()]
}

// Implement Protocol trait (common functionality)
impl Protocol for DynamoProtocol {
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // No async actions for DynamoDB currently
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![send_dynamo_response_action()]
    }
    fn protocol_name(&self) -> &'static str {
        "DynamoDB"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_dynamo_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>DYNAMODB"
    }
    fn keywords(&self) -> Vec<&'static str> {
        // Include the full "dynamodb" spelling: the bare "dynamo" keyword never matched
        // "dynamodb" in free text because the trailing "db" broke the word boundary, so
        // "emulate a DynamoDB table" resolved to nothing.
        vec!["dynamo", "dynamodb", "dynamo db", "aws dynamodb"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Beta)
            .well_known_port(8000)
            .implementation("hyper v1.5 HTTP with manual DynamoDB API")
            .llm_control("All DynamoDB operations (GetItem, PutItem, Query)")
            .e2e_testing(
                "TWO independent clients, neither #[ignore]d and neither able to skip. \
                 (1) aws-sdk-dynamodb, the official Rust SDK, in \
                 tests/server/dynamo/e2e_aws_sdk_test.rs: CreateTable, PutItem/GetItem and \
                 UpdateItem complete through the SDK. \
                 (2) the real `aws` CLI (botocore, Python) in \
                 tests/server/dynamo/real_client_test.rs: ListTables, PutItem and GetItem, \
                 asserting the TYPED attribute values it rendered -- a string under S, a number \
                 under N, a boolean under BOOL. That is the check worth having, because \
                 DynamoDB numbers cross the wire as STRINGS under an N tag and botocore rejects \
                 an item whose tags it does not recognise rather than rendering it as text. \
                 Verified by sending `\"count\":{\"N\":7}` as a JSON number, which the test \
                 then reports. \
                 THE TEST CANNOT REACH REAL AWS, and for this protocol that is not abstract: \
                 the project CLAUDE.md records that this protocol's CLIENT once dropped its \
                 target, let the SDK resolve the production endpoint and signed with ambient \
                 credentials. --endpoint-url is passed on every invocation, the port is asserted \
                 non-zero before the CLI is spawned, and credentials, region, profile and the \
                 EC2 metadata service are overridden in the child's environment. \
                 UNPROVEN, and worth saying plainly: NO SIGNATURE IS VALIDATED -- every request \
                 is served unconditionally and neither Authorization nor X-Amz-Date reaches the \
                 event, so the model cannot make that decision either. Also unproven: Query and \
                 Scan, conditional writes, transactions, streams, and pagination.",
            )
            .notes("Virtual data (no persistence)")
            .max_inbound_bytes(crate::server::dynamo::MAX_REQUEST_BYTES)
            .request_only("DynamoDB is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "DynamoDB-compatible database server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a DynamoDB-compatible server on port 8000"
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        use serde_json::json;

        // Deterministic DynamoDB (JSON protocol) replies routed on the operation.
        // Items use DynamoDB's typed attribute-value shape. No LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "dynamo_request":
    op = event.get("operation", "")
    if op == "GetItem":
        body = json.dumps({"Item": {"id": {"S": "item-1"},
                                    "name": {"S": "Example"}}})
    else:
        body = json.dumps({})
    actions = [{"type": "send_dynamo_response", "status_code": 200, "body": body}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: maintain a real keyed table across requests.
            json!({
                "type": "open_server",
                "port": 8000,
                "base_stack": "dynamo",
                "instruction": "Emulate a DynamoDB table 'Users' keyed by userId. On PutItem remember the item; on GetItem return the stored item for that key (or an empty response if absent); on Query return every remembered item whose userId matches. Format all responses in DynamoDB JSON with typed attribute values."
            }),
            // Script mode: fixed typed responses per operation, no LLM call.
            json!({
                "type": "open_server",
                "port": 8000,
                "base_stack": "dynamo",
                "event_handlers": [{
                    "event_pattern": "dynamo_request",
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
                "port": 8000,
                "base_stack": "dynamo",
                "event_handlers": [{
                    "event_pattern": "dynamo_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_dynamo_response",
                            "status_code": 200,
                            "body": "{}"
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for DynamoProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::dynamo::DynamoServer;
            DynamoServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                false,
                ctx.server_id,
            )
            .await
        })
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        let action_type = action
            .get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing action type"))?;

        match action_type {
            "send_dynamo_response" => {
                let status_code = parse_status_code(&action)?;

                let body = action
                    .get("body")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing body"))?
                    .to_string();

                Ok(ActionResult::Custom {
                    name: "dynamo_response".to_string(),
                    data: json!({
                        "status": status_code,
                        "body": body
                    }),
                })
            }
            _ => Err(anyhow::anyhow!("Unknown action type: {}", action_type)),
        }
    }
}

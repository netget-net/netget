//! AWS SQS protocol actions and event types
//!
//! Defines the actions the LLM can take in response to SQS API requests.

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::LazyLock;

/// SQS protocol handler
pub struct SqsProtocol {
    // Could store connection state here if needed
}

impl SqsProtocol {
    pub fn new() -> Self {
        Self {}
    }
}

/// SQS request event - triggered when an SQS API request is received
pub static SQS_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "sqs_request",
        "An SQS API request arrived. Answer in the **AWS JSON protocol**: this server replies \
         with Content-Type application/x-amz-json-1.0, so the body is a JSON object \
         (`{\"MessageId\": \"...\"}`). SQS also has an older Query API that answers with XML \
         (<SendMessageResponse xmlns=\"http://queue.amazonaws.com/doc/2012-11-05/\">…) — that \
         is a different protocol and a client here cannot parse it, however well-formed it is.",
        json!({
            "type": "send_sqs_response",
            "status_code": 200,
            "body": "{\"MessageId\": \"59c5d728-17e6-4355-a298-1a9364790137\", \"MD5OfMessageBody\": \"5d41402abc4b2a76b9719d911017c592\"}"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "operation".to_string(),
            type_hint: "string".to_string(),
            description: "SQS operation (SendMessage, ReceiveMessage, CreateQueue, etc.)"
                .to_string(),
            required: true,
        },
        Parameter {
            name: "queue_url".to_string(),
            type_hint: "string".to_string(),
            description: "Target queue URL (if available)".to_string(),
            required: false,
        },
        Parameter {
            name: "request_body".to_string(),
            type_hint: "string".to_string(),
            description: "JSON request body".to_string(),
            required: true,
        },
    ])
    .with_actions(vec![send_sqs_response_action()])
    // Only fields `sqs_request` actually carries. `{client_ip}`, `{status}` and
    // `{duration_ms}` were in this template and in none of the event data, and a missing
    // field renders as the empty string — so the INFO line read
    // " SQS SendMessage http://... ->  (ms)" on every request.
    .with_log_template(
        LogTemplate::new()
            .with_info("SQS {operation} {queue_url}")
            .with_debug("SQS {operation} queue={queue_url}")
            .with_trace("SQS request: {json_pretty(.)}"),
    )
});

fn send_sqs_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "send_sqs_response".to_string(),
        description: "Send an SQS response. The body is sent as \
                      Content-Type: application/x-amz-json-1.0, so it must be a JSON object — \
                      never the legacy Query API's XML, which a client on this endpoint cannot \
                      parse."
            .to_string(),
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
                description: "Response body as a JSON object, serialized to a string. This is \
                              the AWS JSON protocol (application/x-amz-json-1.0): a SendMessage \
                              reply is {\"MessageId\": \"...\", \"MD5OfMessageBody\": \"...\"}, \
                              not an <SendMessageResponse> XML document."
                    .to_string(),
                required: true,
            },
        ],
        example: serde_json::json!({
            "type": "send_sqs_response",
            "status_code": 200,
            "body": "{\"MessageId\": \"msg-123\", \"MD5OfMessageBody\": \"d41d8cd98f00b204e9800998ecf8427e\"}"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> {status_code} ({body_len}B)")
                .with_debug("SQS response: status={status_code}")
                .with_trace("SQS response body: {body}"),
        ),
    }
}

/// Read and validate the model-supplied `status_code`.
///
/// The old `as u64 as u16` cast wrapped silently, so a status of 65736 became 200 and a
/// status of 99 or 1000 reached `Response::builder().status()`, which rejects it - and the
/// `.unwrap()` on the other side of that turned a typo in model output into a panic that
/// killed the connection task. Reject it here instead, where the message reaches the model.
pub(crate) fn parse_status_code(action: &Value) -> Result<u16> {
    let raw = action
        .get("status_code")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow::anyhow!("Missing or invalid status_code: expected a number"))?;

    if !(100..=599).contains(&raw) {
        return Err(anyhow::anyhow!(
            "Invalid status_code {raw}: must be an HTTP status between 100 and 599. \
             SQS uses 200 for success and 400 with an {{\"__type\": ..., \"message\": ...}} \
             body for client errors."
        ));
    }

    Ok(raw as u16)
}

pub fn get_sqs_event_types() -> Vec<EventType> {
    vec![SQS_REQUEST_EVENT.clone()]
}

// Implement Protocol trait (common functionality)
impl Protocol for SqsProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        // Deliberately empty. `default_visibility_timeout`, `default_message_retention` and
        // `max_receive_count` used to be declared here, but the server holds no queue state
        // to apply them to and `spawn()` never read them - the LLM owns visibility and
        // retention behaviour entirely, through the instruction. Declaring them promised
        // enforcement that did not exist.
        vec![]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        // No async actions for SQS currently (all operations are request-driven)
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![send_sqs_response_action()]
    }
    fn protocol_name(&self) -> &'static str {
        "SQS"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_sqs_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>SQS"
    }
    fn keywords(&self) -> Vec<&'static str> {
        // "queue" alone is intentionally absent: it collided with AMQP. SQS is chosen by
        // its AWS-specific names and the two-word "message queue" phrase.
        vec!["sqs", "message queue", "sqs queue", "aws sqs"]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};

        ProtocolMetadataV2::builder()
            // Beta: exercised against a real, independent client — aws-sdk-sqs —
            // covering the AWS SDK issuing real SQS operations. Not Stable: Stable additionally wants spec
            // compliance and scripting support reviewed, which has not been done here.
            .state(DevelopmentState::Beta)
            .implementation("hyper v1.5 HTTP with AWS JSON protocol")
            .llm_control("All SQS operations (SendMessage, ReceiveMessage, DeleteMessage)")
            .e2e_testing(
                "TWO independent clients, neither #[ignore]d and neither able to skip. \
                 (1) aws-sdk-sqs, the official Rust SDK, in tests/server/sqs/e2e_test.rs. \
                 (2) the real `aws` CLI (botocore, Python -- a different SDK generation and a \
                 different serialiser) in tests/server/sqs/real_client_test.rs, completing \
                 CreateQueue, SendMessage and ReceiveMessage and asserting on what it PRINTED. \
                 Rendering is what the second client adds: a field name or JSON shape the Rust \
                 SDK tolerates through its generated deserialiser shows up there as a missing \
                 column. Verified by renaming MessageId to messageId in the reply, which the \
                 test then reports. \
                 THE TEST CANNOT REACH REAL AWS, and that is enforced rather than assumed: \
                 --endpoint-url is passed on every invocation, the port is asserted non-zero \
                 before the CLI is spawned, and credentials, region, profile and the EC2 \
                 metadata service are overridden in the child's environment. The reason is in \
                 the project CLAUDE.md -- the DynamoDB CLIENT once dropped its target, let the \
                 SDK resolve the production endpoint, and signed with ambient credentials. \
                 UNPROVEN, and worth saying plainly: NO SIGNATURE IS VALIDATED. This server \
                 serves every request unconditionally and does not put Authorization or \
                 X-Amz-Date into the event, so the model cannot make that decision either. \
                 Also unproven: long polling, batch operations, dead-letter queues, FIFO \
                 queues, and the query-protocol wire format older SDKs use.",
            )
            .notes("Virtual queues (no persistence); no auth; visibility timeouts are the LLM's job, the server tracks nothing")
            .max_inbound_bytes(crate::server::sqs::MAX_REQUEST_BYTES)
            .request_only("SQS is HTTP request/response; a server cannot send a peer anything unprompted")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "AWS SQS-compatible message queue server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start an AWS SQS-compatible queue server on port 9324"
    }
    fn group_name(&self) -> &'static str {
        "Database"
    }

    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        // Deterministic SQS (AWS JSON protocol) replies routed on the operation.
        // The body is a JSON string in the SQS response shape. No LLM call.
        let script = r#"import json, sys
data = json.load(sys.stdin)
event = data["event"]
if data["event_type_id"] == "sqs_request":
    op = event.get("operation", "")
    if op == "SendMessage":
        body = json.dumps({"MessageId": "00000000-0000-0000-0000-000000000001",
                           "MD5OfMessageBody": "d41d8cd98f00b204e9800998ecf8427e"})
    elif op == "ReceiveMessage":
        body = json.dumps({"Messages": []})
    else:
        body = json.dumps({})
    actions = [{"type": "send_sqs_response", "status_code": 200, "body": body}]
else:
    actions = []
print(json.dumps({"actions": actions}))"#;

        StartupExamples::new(
            // LLM mode: keep a real FIFO of messages across requests.
            json!({
                "type": "open_server",
                "port": 9324,
                "base_stack": "sqs",
                "instruction": "Act as an SQS queue named 'jobs'. Accept SendMessage requests and remember each message body in order; on ReceiveMessage return the oldest not-yet-received message with a fresh receipt handle, and an empty response once the queue is drained."
            }),
            // Script mode: fixed AWS-JSON responses per operation, no LLM call.
            json!({
                "type": "open_server",
                "port": 9324,
                "base_stack": "sqs",
                "event_handlers": [{
                    "event_pattern": "sqs_request",
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
                "port": 9324,
                "base_stack": "sqs",
                "event_handlers": [{
                    "event_pattern": "sqs_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "send_sqs_response",
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
impl Server for SqsProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::sqs::SqsServer;
            SqsServer::spawn_with_llm_actions(
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
            "send_sqs_response" => {
                let status_code = parse_status_code(&action)?;

                let body = action
                    .get("body")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("Missing body"))?
                    .to_string();

                Ok(ActionResult::Custom {
                    name: "sqs_response".to_string(),
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

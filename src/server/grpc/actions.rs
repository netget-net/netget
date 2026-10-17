//! gRPC protocol actions implementation

use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;
use tracing::debug;

/// gRPC protocol action handler
pub struct GrpcProtocol;

impl GrpcProtocol {
    pub fn new() -> Self {
        Self
    }

    fn execute_grpc_unary_response(&self, action: serde_json::Value) -> Result<ActionResult> {
        let message = action
            .get("message")
            .context("Missing 'message' parameter in grpc_unary_response")?;

        debug!("gRPC unary response: {}", serde_json::to_string(message)?);

        // Return as Custom action result so server can encode to protobuf
        Ok(ActionResult::Custom {
            name: "grpc_unary_response".to_string(),
            data: json!({ "message": message }),
        })
    }

    fn execute_grpc_error(&self, action: serde_json::Value) -> Result<ActionResult> {
        let code = action
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or("INTERNAL");

        let message = action
            .get("message")
            .and_then(|v| v.as_str())
            .context("Missing 'message' parameter in grpc_error")?;

        debug!("gRPC error response: {} - {}", code, message);

        // Return as Custom action result so server can construct proper gRPC error
        Ok(ActionResult::Custom {
            name: "grpc_error".to_string(),
            data: json!({
                "code": code,
                "message": message
            }),
        })
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for GrpcProtocol {
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        use crate::llm::actions::ParameterDefinition;
        vec![
                ParameterDefinition {
                    name: "proto_schema".to_string(),
                    type_hint: "string".to_string(),
                    description: "Protobuf schema definition. IMPORTANT: For LLM responses, use inline .proto text (proto3 syntax). LLMs should NOT use base64-encoded FileDescriptorSet (truncation issues). Alternatively, provide path to .proto file on disk.".to_string(),
                    required: true,
                    example: json!("syntax = \"proto3\"; package test; service UserService { rpc GetUser(UserId) returns (User); } message UserId { int32 id = 1; } message User { int32 id = 1; string name = 2; string email = 3; }"),
                    default: None,
                },
                ParameterDefinition {
                    name: "enable_reflection".into(), type_hint: "boolean".into(), required: false,
                    description: "Serve bounded gRPC v1/v1alpha reflection of the startup schema".into(),
                    example: json!(true), default: Some(json!(super::streaming::DEFAULT_REFLECTION)),
                },
                ParameterDefinition {
                    name: "stream_timeout_secs".into(), type_hint: "integer".into(), required: false,
                    description: "Whole streaming RPC deadline, 1..3600 seconds, shortened by grpc-timeout".into(),
                    example: json!(300), default: Some(json!(super::streaming::DEFAULT_TIMEOUT_SECS)),
                },
            ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        stream_actions()
            .into_iter()
            .filter(|action| action.name != "grpc_stream_wait" && action.name != "grpc_error")
            .collect()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut actions = vec![grpc_unary_response_action()];
        actions.extend(stream_actions());
        actions
    }
    fn protocol_name(&self) -> &'static str {
        "gRPC"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        get_grpc_event_types()
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP2>GRPC"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["grpc", "grpcserver", "protobuf"]
    }

    /// `protoc` must be on PATH at **runtime**, not merely at build time.
    ///
    /// `proto_schema` is a required startup parameter, and the two forms a caller is told to
    /// use — a `.proto` path on disk and inline proto3 text — are compiled by shelling out to
    /// `protoc` (`mod.rs`, via `Command::new`). A pre-compiled descriptor set (base64, or a
    /// `.pb` file) is decoded directly and needs no `protoc`; [`Self::startup_dependencies`]
    /// drops the dependency for exactly those, so the startup gate refuses only a start that
    /// would really fail.
    ///
    /// Declaring it here means `server_startup` refuses with the installation hint before
    /// registering the server, and the TUI and the model's protocol list exclude gRPC on a host
    /// that lacks it, rather than everyone discovering it from a failure part-way through
    /// startup.
    ///
    /// Note this is unrelated to `etcd`/`kubernetes`/`zookeeper`, which need `protoc` to
    /// *compile* (prost/tonic build scripts) and not to run.
    fn get_dependencies(&self) -> Vec<crate::protocol::dependencies::ProtocolDependency> {
        let mut deps =
            crate::llm::actions::protocol_trait::default_dependencies_from_privilege(self);
        deps.push(crate::protocol::dependencies::ProtocolDependency::ToolInPath("protoc"));
        deps
    }

    fn startup_dependencies(
        &self,
        startup_params: Option<&serde_json::Value>,
    ) -> Vec<crate::protocol::dependencies::ProtocolDependency> {
        let precompiled = startup_params
            .and_then(|p| p.get("proto_schema"))
            .and_then(|s| s.as_str())
            .map(|schema| schema.trim().ends_with(".pb") || is_base64_descriptor_set(schema.trim()))
            .unwrap_or(false);
        let mut deps = self.get_dependencies();
        if precompiled {
            deps.retain(|d| {
                *d != crate::protocol::dependencies::ProtocolDependency::ToolInPath("protoc")
            });
        }
        deps
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
        ProtocolMetadataV2::builder()
            .state(DevelopmentState::Experimental)
            .implementation("Dynamic protobuf services over hyper HTTP/2; tonic owns streaming and reflection framing, compression and trailers. Immutable bounded startup schema.")
            .llm_control("Typed field-name JSON for unary requests and stream open/message/input-close/tick events; send, finish, cancel and wait controls. No protocol domain store.")
            .e2e_testing("Mandatory independent grpcurl1.9.4 and generated grpcio1.75.1 peers exercise unary success/error, all three stream shapes, gzip and v1/v1alpha reflection; paired NetGet client/server and cancellation/bounds regressions in tests/server/grpc and tests/client/grpc. Peers fail when absent.")
            .notes("Experimental expanded scope. New streams exclude schemas containing bytes fields; legacy unary bytes/base64 behavior remains. Reflection is enabled by default and can be disabled. Receiver TLS, mTLS, streaming retries, load balancing, reflection authentication and pcap/fuzz evidence are outside the validated scope. Legacy unary request compression remains rejected.")
            .max_inbound_bytes(crate::server::grpc::MAX_REQUEST_BYTES)
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "gRPC server"
    }
    fn example_prompt(&self) -> &'static str {
        "Start a gRPC server on port 50051 with this schema: service UserService { rpc GetUser(UserId) returns (User); }"
    }
    fn group_name(&self) -> &'static str {
        "AI & API"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;

        StartupExamples::new(
            // LLM mode: instruction-based
            json!({
                "type": "open_server",
                "port": 50051,
                "base_stack": "grpc",
                "instruction": "gRPC server with UserService. Respond to GetUser with user details",
                "startup_params": {
                    "proto_schema": "syntax = \"proto3\"; package test; service UserService { rpc GetUser(UserId) returns (User); } message UserId { int32 id = 1; } message User { int32 id = 1; string name = 2; string email = 3; }"
                }
            }),
            // Script mode: event_handlers with script handler
            json!({
                "type": "open_server",
                "port": 50051,
                "base_stack": "grpc",
                "startup_params": {
                    "proto_schema": "syntax = \"proto3\"; package test; service Calculator { rpc Add(AddRequest) returns (AddResponse); } message AddRequest { int32 a = 1; int32 b = 2; } message AddResponse { int32 result = 1; }"
                },
                "event_handlers": [{
                    "event_pattern": "grpc_unary_request",
                    "handler": {
                        "type": "script",
                        "language": "python",
                        "code": "import json,sys\nd=json.load(sys.stdin)\nreq=d['event']['request']\nprint(json.dumps({'actions':[{'type':'grpc_unary_response','message':{'result':req['a']+req['b']}}]}))"
                    }
                }]
            }),
            // Static mode: event_handlers with static actions
            json!({
                "type": "open_server",
                "port": 50051,
                "base_stack": "grpc",
                "startup_params": {
                    "proto_schema": "syntax = \"proto3\"; package test; service Greeter { rpc SayHello(HelloRequest) returns (HelloReply); } message HelloRequest { string name = 1; } message HelloReply { string message = 1; }"
                },
                "event_handlers": [{
                    "event_pattern": "grpc_unary_request",
                    "handler": {
                        "type": "static",
                        "actions": [{
                            "type": "grpc_unary_response",
                            "message": {"message": "Hello, World!"}
                        }]
                    }
                }]
            }),
        )
    }
}

// Implement Server trait (server-specific functionality)
impl Server for GrpcProtocol {
    fn spawn(
        &self,
        ctx: crate::protocol::SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::server::grpc::GrpcServer;
            GrpcServer::spawn_with_llm_actions(
                ctx.legacy_listen_addr(),
                ctx.llm_client,
                ctx.state,
                ctx.status_tx,
                ctx.server_id,
                ctx.startup_params,
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
            "grpc_unary_response" => self.execute_grpc_unary_response(action),
            "grpc_error" => self.execute_grpc_error(action),
            "grpc_stream_send" | "grpc_stream_finish" | "grpc_stream_cancel"
            | "grpc_stream_wait" => {
                if action_type == "grpc_stream_send" {
                    anyhow::ensure!(
                        action["message"].is_object(),
                        "message must be a field-name JSON object"
                    );
                }
                if action_type == "grpc_stream_wait" {
                    anyhow::ensure!(
                        action["milliseconds"]
                            .as_u64()
                            .is_some_and(|n| (1..=1000).contains(&n)),
                        "milliseconds must be 1..1000"
                    );
                }
                if let Some(id) = action.get("stream_id") {
                    anyhow::ensure!(
                        id.as_u64()
                            .is_some_and(|id| (1..=u64::from(u32::MAX)).contains(&id)),
                        "stream_id must be 1..4294967295"
                    );
                }
                Ok(ActionResult::Custom {
                    name: action_type.to_owned(),
                    data: action,
                })
            }
            _ => Err(anyhow::anyhow!("Unknown gRPC action: {}", action_type)),
        }
    }
}

// ============================================================================
// Action Definitions
// ============================================================================

fn grpc_unary_response_action() -> ActionDefinition {
    ActionDefinition {
        name: "grpc_unary_response".to_string(),
        description: "Send gRPC unary response with JSON message".to_string(),
        parameters: vec![Parameter {
            name: "message".to_string(),
            type_hint: "object".to_string(),
            description: "Response message as JSON object matching protobuf schema".to_string(),
            required: true,
        }],
        example: json!({
            "type": "grpc_unary_response",
            "message": {
                "id": 123,
                "name": "Alice",
                "email": "alice@example.com"
            }
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> gRPC response")
                .with_debug("gRPC grpc_unary_response"),
        ),
    }
}

fn grpc_error_action() -> ActionDefinition {
    ActionDefinition {
        name: "grpc_error".to_string(),
        description: "Return gRPC error with status code and message".to_string(),
        parameters: vec![
            Parameter {
                name: "code".to_string(),
                type_hint: "string".to_string(),
                description:
                    "gRPC status code (OK, CANCELLED, INVALID_ARGUMENT, NOT_FOUND, INTERNAL, etc.)"
                        .to_string(),
                required: false,
            },
            Parameter {
                name: "message".to_string(),
                type_hint: "string".to_string(),
                description: "Terminal gRPC status explanation sent to the peer".to_string(),
                required: true,
            },
        ],
        example: json!({
            "type": "grpc_error",
            "code": "NOT_FOUND",
            "message": "User not found"
        }),
        log_template: Some(
            LogTemplate::new()
                .with_info("-> gRPC error {code}")
                .with_debug("gRPC grpc_error: code={code}, message={message}"),
        ),
    }
}

// ============================================================================
// gRPC Action Constants
// ============================================================================

pub static GRPC_UNARY_RESPONSE_ACTION: LazyLock<ActionDefinition> =
    LazyLock::new(|| grpc_unary_response_action());
pub static GRPC_ERROR_ACTION: LazyLock<ActionDefinition> = LazyLock::new(|| grpc_error_action());

// ============================================================================
// gRPC Event Type Constants
// ============================================================================

/// gRPC unary request event - triggered when client makes a unary RPC call
pub static GRPC_UNARY_REQUEST_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "grpc_unary_request",
        "gRPC unary RPC request received from client",
        json!({
            "type": "grpc_unary_response",
            "message": {
                "id": 123,
                "name": "Alice",
                "email": "alice@example.com"
            }
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "service".to_string(),
            type_hint: "string".to_string(),
            description: "Service name (e.g., 'UserService')".to_string(),
            required: true,
        },
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "Method name (e.g., 'GetUser')".to_string(),
            required: true,
        },
        Parameter {
            name: "request".to_string(),
            type_hint: "object".to_string(),
            description: "Request message as JSON object".to_string(),
            required: true,
        },
        Parameter {
            name: "expected_response_schema".to_string(),
            type_hint: "object".to_string(),
            description: "Expected response schema as JSON Schema".to_string(),
            required: false,
        },
    ])
    .with_actions(vec![
        GRPC_UNARY_RESPONSE_ACTION.clone(),
        GRPC_ERROR_ACTION.clone(),
    ])
    .with_log_template(
        LogTemplate::new()
            .with_info("gRPC {client_ip} {service}/{method}")
            .with_debug("gRPC method {service}/{method} from {client_ip}:{client_port}")
            .with_trace("gRPC: {json_pretty(.)}"),
    )
});

/// Get gRPC event types
pub fn get_grpc_event_types() -> Vec<EventType> {
    vec![
        GRPC_UNARY_REQUEST_EVENT.clone(),
        GRPC_STREAM_OPENED_EVENT.clone(),
        GRPC_STREAM_MESSAGE_EVENT.clone(),
        GRPC_STREAM_INPUT_CLOSED_EVENT.clone(),
        GRPC_STREAM_TICK_EVENT.clone(),
    ]
}

fn stream_actions() -> Vec<ActionDefinition> {
    let mut actions = Vec::new();
    for (name, description, extra, example) in [
        ("grpc_stream_send", "Queue one typed response on the current stream; injected actions require stream_id", Some(("message", "object", "Field-name response JSON matching expected_response_schema")), json!({"type":"grpc_stream_send","stream_id":1,"message":{"name":"update","value":1}})),
        ("grpc_stream_finish", "Finish this RPC with OK after pending responses; client-streaming requires half-close and one response", None, json!({"type":"grpc_stream_finish","stream_id":1})),
        ("grpc_stream_cancel", "Cancel an active RPC; injected actions require stream_id", None, json!({"type":"grpc_stream_cancel","stream_id":1})),
        ("grpc_stream_wait", "Continue reading input and request a subscription tick after 1..1000 milliseconds", Some(("milliseconds", "integer", "Delay before the next handler tick, 1..1000")), json!({"type":"grpc_stream_wait","milliseconds":100})),
    ] {
        let mut parameters = vec![Parameter { name:"stream_id".into(), type_hint:"integer".into(), required:false, description:"Active RPC id; required for peer injection, implicit within an event handler".into() }];
        if let Some((name, hint, description)) = extra { parameters.push(Parameter { name:name.into(), type_hint:hint.into(), required:true, description:description.into() }); }
        actions.push(ActionDefinition { name:name.into(), description:description.into(), parameters, example, log_template:Some(LogTemplate::new().with_info(format!("gRPC {name} queued for the active RPC"))) });
    }
    actions.push(grpc_error_action());
    actions
}
fn stream_event(name: &'static str, description: &'static str) -> EventType {
    EventType::new(
        name,
        description,
        json!({"type":"grpc_stream_wait","milliseconds":100}),
    )
    .with_parameters(vec![
        Parameter {
            name: "stream_id".into(),
            type_hint: "integer".into(),
            required: true,
            description: "Active RPC correlation id".into(),
        },
        Parameter {
            name: "service".into(),
            type_hint: "string".into(),
            required: true,
            description: "Fully qualified service name".into(),
        },
        Parameter {
            name: "method".into(),
            type_hint: "string".into(),
            required: true,
            description: "Protobuf RPC method within the declared service".into(),
        },
        Parameter {
            name: "message".into(),
            type_hint: "object|null".into(),
            required: false,
            description: "Decoded typed request message, or null for lifecycle/tick events".into(),
        },
        Parameter {
            name: "expected_response_schema".into(),
            type_hint: "object".into(),
            required: true,
            description: "Response fields and cardinalities; streaming excludes bytes fields"
                .into(),
        },
    ])
    .with_actions(stream_actions())
}
pub static GRPC_STREAM_OPENED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    stream_event(
        "grpc_stream_opened",
        "Streaming RPC opened; server-streaming carries its one decoded request",
    )
});
pub static GRPC_STREAM_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    stream_event(
        "grpc_stream_message",
        "A decoded client-streaming or bidirectional message arrived",
    )
});
pub static GRPC_STREAM_INPUT_CLOSED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    stream_event(
        "grpc_stream_input_closed",
        "Client half-closed its request stream; client-streaming now permits one response",
    )
});
pub static GRPC_STREAM_TICK_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    stream_event(
        "grpc_stream_tick",
        "Requested subscription interval elapsed; send updates, wait or finish",
    )
});

/// Whether `schema` is a base64-encoded `FileDescriptorSet` — the form `mod.rs` decodes
/// directly, without `protoc`.
fn is_base64_descriptor_set(schema: &str) -> bool {
    use base64::Engine as _;
    use prost::Message as _;
    if schema.len() > (4usize * 1024 * 1024).div_ceil(3) * 4 {
        return false;
    }
    base64::engine::general_purpose::STANDARD
        .decode(schema)
        .map(|bytes| prost_types::FileDescriptorSet::decode(bytes.as_slice()).is_ok())
        .unwrap_or(false)
}

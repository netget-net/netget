//! gRPC client protocol actions implementation

use crate::protocol::log_template::LogTemplate;

use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter, ParameterDefinition,
};
use crate::protocol::EventType;
use crate::state::app_state::AppState;
use anyhow::{Context, Result};
use serde_json::json;
use std::sync::LazyLock;

/// gRPC client connected event
pub static GRPC_CLIENT_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "grpc_connected",
        "gRPC client initialized and ready to call RPC methods",
        json!({
            "type": "call_grpc_method",
            "service": "calculator.Calculator",
            "method": "Add",
            "request": {"a": 5, "b": 3}
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "server_addr".to_string(),
            type_hint: "string".to_string(),
            description: "gRPC server address".to_string(),
            required: true,
        },
        Parameter {
            name: "services".to_string(),
            type_hint: "array".to_string(),
            description: "Available service names from schema".to_string(),
            required: true,
        },
    ])
});

/// gRPC client response received event
pub static GRPC_CLIENT_RESPONSE_RECEIVED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "grpc_response_received",
        "gRPC response received from server",
        json!({
            "type": "call_grpc_method",
            "service": "calculator.Calculator",
            "method": "Multiply",
            "request": {"a": 2, "b": 3}
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "service".to_string(),
            type_hint: "string".to_string(),
            description: "Fully qualified protobuf service name".to_string(),
            required: true,
        },
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "Protobuf RPC method within the declared service".to_string(),
            required: true,
        },
        Parameter {
            name: "response".to_string(),
            type_hint: "object".to_string(),
            description: "Response message as JSON".to_string(),
            required: true,
        },
    ])
});

/// gRPC client error event
pub static GRPC_CLIENT_ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "grpc_error",
        "gRPC error received from server",
        json!({
            "type": "wait_for_more"
        }),
    )
    .with_parameters(vec![
        Parameter {
            name: "service".to_string(),
            type_hint: "string".to_string(),
            description: "Fully qualified protobuf service name".to_string(),
            required: true,
        },
        Parameter {
            name: "method".to_string(),
            type_hint: "string".to_string(),
            description: "Protobuf RPC method within the declared service".to_string(),
            required: true,
        },
        Parameter {
            name: "code".to_string(),
            type_hint: "string".to_string(),
            description: "gRPC status code".to_string(),
            required: true,
        },
        Parameter {
            name: "message".to_string(),
            type_hint: "string".to_string(),
            description: "Terminal gRPC status explanation from the peer".to_string(),
            required: true,
        },
    ])
});

/// gRPC client protocol action handler
pub struct GrpcClientProtocol;

impl GrpcClientProtocol {
    pub fn new() -> Self {
        Self
    }
}

// Implement Protocol trait (common functionality)
impl Protocol for GrpcClientProtocol {
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
                ParameterDefinition {
                    name: "proto_schema".to_string(),
                    description: "Optional inline proto3 text or .proto/.pb path; omit to discover the bounded schema through server reflection. Models should use inline text, not base64 descriptors.".to_string(),
                    type_hint: "string".to_string(),
                    required: false,
                    example: json!("CpUCCg9jYWxjdWxhdG9yLnByb3RvEgpjYWxjdWxhdG9yIikKCkFkZFJlcXVlc3QSCwoDYQgBIAEoBVIBYRILCgNiCAIgASgFUgFiIiIKC0FkZFJlc3BvbnNlEhMKBnJlc3VsdBgBIAEoBVIGcmVzdWx0MkIKCkNhbGN1bGF0b3ISNAoDQWRkEhYuY2FsY3VsYXRvci5BZGRSZXF1ZXN0Gh0uY2FsY3VsYXRvci5BZGRSZXNwb25zZSIAYgZwcm90bzM="),
                    default: None,
                },
                ParameterDefinition {
                    name: "use_tls".to_string(),
                    description: "Whether to use TLS for connection (default: false)".to_string(),
                    type_hint: "boolean".to_string(),
                    required: false,
                    example: json!(false),
                    default: Some(json!(super::DEFAULT_TLS)),
                },
                ParameterDefinition {
                    name:"connect_timeout_secs".into(),type_hint:"integer".into(),required:false,description:"Whole schema/connection deadline, 1..60 seconds".into(),example:json!(10),default:Some(json!(super::CONNECT_TIMEOUT_SECS)),
                },
                ParameterDefinition {
                    name:"stream_timeout_secs".into(),type_hint:"integer".into(),required:false,description:"Whole streaming RPC deadline, 1..3600 seconds".into(),example:json!(300),default:Some(json!(super::streaming::DEFAULT_STREAM_TIMEOUT)),
                },
                ParameterDefinition {
                    name:"idle_timeout_secs".into(),type_hint:"integer".into(),required:false,description:"Idle with no active operations or handlers, 1..3600 seconds".into(),example:json!(120),default:Some(json!(super::streaming::DEFAULT_IDLE_TIMEOUT)),
                },
                ParameterDefinition {
                    name:"server_name".into(),type_hint:"string".into(),required:false,description:"Verified TLS certificate hostname, default endpoint hostname; requires use_tls".into(),example:json!("localhost"),default:None,
                },
                ParameterDefinition {
                    name:"ca_file".into(),type_hint:"string".into(),required:false,description:"Optional trusted PEM CA file, regular file at most 1 MiB; requires use_tls".into(),example:json!("/path/to/ca.pem"),default:None,
                },
            ]
    }
    fn get_async_actions(&self, _state: &AppState) -> Vec<ActionDefinition> {
        let mut actions = vec![
            ActionDefinition {
                name: "call_grpc_method".to_string(),
                description: "Call a gRPC method with the given request".to_string(),
                parameters: vec![
                    Parameter {
                        name: "service".to_string(),
                        type_hint: "string".to_string(),
                        description: "Fully qualified service name (e.g., 'calculator.Calculator')"
                            .to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "method".to_string(),
                        type_hint: "string".to_string(),
                        description: "Method name (e.g., 'Add')".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "request".to_string(),
                        type_hint: "object".to_string(),
                        description: "Request message as JSON object".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "metadata".to_string(),
                        type_hint: "object".to_string(),
                        description: "Optional gRPC metadata (headers)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "call_grpc_method",
                    "service": "calculator.Calculator",
                    "method": "Add",
                    "request": {"a": 5, "b": 3},
                    "metadata": {"auth-token": "secret"}
                }),
                log_template: Some(
                    LogTemplate::new().with_info("gRPC {service}/{method} call queued"),
                ),
            },
            ActionDefinition {
                name: "disconnect".to_string(),
                description: "Disconnect from the gRPC server".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "disconnect"
                }),
                log_template: Some(LogTemplate::new().with_info("gRPC client disconnected")),
            },
        ];
        actions.extend(stream_actions());
        actions
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let mut actions = vec![
            ActionDefinition {
                name: "call_grpc_method".to_string(),
                description: "Call another gRPC method in response to received data".to_string(),
                parameters: vec![
                    Parameter {
                        name: "service".to_string(),
                        type_hint: "string".to_string(),
                        description: "Fully qualified service name".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "method".to_string(),
                        type_hint: "string".to_string(),
                        description: "Protobuf RPC method within the declared service".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "request".to_string(),
                        type_hint: "object".to_string(),
                        description: "Request message as JSON object".to_string(),
                        required: true,
                    },
                    Parameter {
                        name: "metadata".to_string(),
                        type_hint: "object".to_string(),
                        description: "Optional gRPC metadata (headers)".to_string(),
                        required: false,
                    },
                ],
                example: json!({
                    "type": "call_grpc_method",
                    "service": "calculator.Calculator",
                    "method": "Multiply",
                    "request": {"a": 2, "b": 3}
                }),
                log_template: Some(
                    LogTemplate::new().with_info("gRPC {service}/{method} follow-up call queued"),
                ),
            },
            ActionDefinition {
                name: "wait_for_more".to_string(),
                description: "Wait without making another call".to_string(),
                parameters: vec![],
                example: json!({
                    "type": "wait_for_more"
                }),
                log_template: Some(
                    LogTemplate::new().with_info("Waiting for another gRPC response"),
                ),
            },
        ];
        actions.extend(stream_actions());
        actions
    }
    fn protocol_name(&self) -> &'static str {
        "gRPC"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            GRPC_CLIENT_CONNECTED_EVENT.clone(),
            GRPC_CLIENT_RESPONSE_RECEIVED_EVENT.clone(),
            GRPC_CLIENT_ERROR_EVENT.clone(),
            GRPC_CLIENT_STREAM_OPENED_EVENT.clone(),
            GRPC_CLIENT_STREAM_MESSAGE_EVENT.clone(),
            GRPC_CLIENT_STREAM_INPUT_READY_EVENT.clone(),
            GRPC_CLIENT_STREAM_ENDED_EVENT.clone(),
        ]
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP/2>gRPC"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["grpc", "grpc client", "connect to grpc", "rpc"]
    }
    /// The gRPC client shells out to `protoc`, exactly as the server does.
    ///
    /// `src/client/grpc/mod.rs` runs `protoc --descriptor_set_out=/dev/stdout` to compile the
    /// inline `.proto` text a caller supplies, so without the binary on PATH that schema form
    /// cannot load at all. The *server* has declared this since the dependency mechanism was
    /// adopted; the client shells out to the same binary and did not, so a host without
    /// `protoc` was told about one half of the pair and discovered the other from a failure.
    ///
    /// Note this is a genuine **runtime** dependency, unlike `etcd`/`kubernetes`/`zookeeper`,
    /// whose `protoc` use is in a build script and is finished before the binary exists.
    fn get_dependencies(&self) -> Vec<crate::protocol::dependencies::ProtocolDependency> {
        let mut deps =
            crate::llm::actions::protocol_trait::default_dependencies_from_privilege(self);
        deps.push(crate::protocol::dependencies::ProtocolDependency::ToolInPath("protoc"));
        deps
    }

    /// Reflection and precompiled descriptors need no protoc; proto text/path does.
    fn startup_dependencies(
        &self,
        startup_params: Option<&serde_json::Value>,
    ) -> Vec<crate::protocol::dependencies::ProtocolDependency> {
        let precompiled = startup_params
            .and_then(|p| p.get("proto_schema"))
            .and_then(|s| s.as_str())
            .map(|schema| schema.trim().ends_with(".pb") || is_base64_descriptor_set(schema))
            .unwrap_or(true);
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
            .implementation("Bounded dynamic tonic gRPC client with unary and all three streaming forms, v1/v1alpha reflection discovery and verified TLS")
            .llm_control("Typed request/response fields and owned start/send/input-half-close/cancel controls; bounded input-ready events report queue availability")
            .e2e_testing("Mandatory generated grpcio1.75.1 peer and NetGet pair in tests/client/grpc/streaming_test.rs; reflection, stream shapes, gzip, TLS verification, cancellation, deadlines and bounded parked handlers. Legacy unary checks are retained.")
            .notes("Experimental expanded scope. Streaming bytes fields and binary metadata are excluded; legacy unary bytes behavior is preserved. One endpoint, no automatic reconnect or streaming retry, no mTLS.")
            .history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn description(&self) -> &'static str {
        "gRPC client for calling RPC services"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to gRPC server at localhost:50051 and call Calculator.Add with a=5, b=3"
    }
    fn group_name(&self) -> &'static str {
        "RPC & API"
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        use crate::llm::actions::StartupExamples;
        let schema = "syntax = \"proto3\"; package calculator; service Calculator { rpc Add(Input) returns (Output); } message Input { int32 a = 1; int32 b = 2; } message Output { int32 result = 1; }";
        let call = json!({"type":"call_grpc_method","service":"calculator.Calculator","method":"Add","request":{"a":5,"b":3}});
        StartupExamples::new(
            json!({"type":"open_client","remote_addr":"localhost:50051","base_stack":"grpc",
                "instruction":"Call calculator.Calculator/Add with a=5, b=3. Report the decoded result and disconnect.","startup_params":{"proto_schema":schema}}),
            json!({"type":"open_client","remote_addr":"localhost:50051","base_stack":"grpc","startup_params":{"proto_schema":schema},
                "event_handlers":[{"event_pattern":"*","handler":{"type":"script","language":"python",
                    "code":"import json,sys\nd=json.load(sys.stdin)\na=[{'type':'wait_for_more'}]\nif d['event_type_id']=='grpc_connected': a=[{'type':'call_grpc_method','service':'calculator.Calculator','method':'Add','request':{'a':5,'b':3}}]\nelif d['event_type_id'] in ('grpc_response_received','grpc_error'): a=[{'type':'disconnect'}]\nprint(json.dumps({'actions':a}))"}}]}),
            json!({"type":"open_client","remote_addr":"localhost:50051","base_stack":"grpc","startup_params":{"proto_schema":schema},
                "event_handlers":[{"event_pattern":"grpc_connected","handler":{"type":"static","actions":[call]}},
                    {"event_pattern":"grpc_response_received","handler":{"type":"static","actions":[{"type":"disconnect"}]}},
                    {"event_pattern":"*","handler":{"type":"static","actions":[{"type":"wait_for_more"}]}}]}),
        )
    }
}

// Implement Client trait (client-specific functionality)
impl Client for GrpcClientProtocol {
    fn connect(
        &self,
        ctx: crate::protocol::ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(async move {
            use crate::client::grpc::GrpcClient;
            GrpcClient::connect_with_llm_actions(
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
            "call_grpc_method" => {
                let service = action
                    .get("service")
                    .and_then(|v| v.as_str())
                    .context("Missing 'service' field")?
                    .to_string();

                let method = action
                    .get("method")
                    .and_then(|v| v.as_str())
                    .context("Missing 'method' field")?
                    .to_string();

                let request = action
                    .get("request")
                    .context("Missing 'request' field")?
                    .clone();

                let metadata = action.get("metadata").and_then(|v| v.as_object()).cloned();

                // Return custom result with RPC call data
                Ok(ClientActionResult::Custom {
                    name: "grpc_call".to_string(),
                    data: json!({
                        "service": service,
                        "method": method,
                        "request": request,
                        "metadata": metadata,
                    }),
                })
            }
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            "grpc_stream_start" | "grpc_stream_send" | "grpc_stream_finish"
            | "grpc_stream_cancel" => {
                anyhow::ensure!(
                    action["stream_id"]
                        .as_u64()
                        .is_some_and(|id| (1..=u64::from(u32::MAX)).contains(&id)),
                    "stream_id must be 1..4294967295"
                );
                if action_type == "grpc_stream_start" {
                    anyhow::ensure!(
                        action["service"].is_string() && action["method"].is_string(),
                        "service and method must be strings"
                    );
                }
                if action_type == "grpc_stream_send" {
                    anyhow::ensure!(
                        action["message"].is_object(),
                        "message must be field-name JSON"
                    );
                }
                Ok(ClientActionResult::Custom {
                    name: action_type.to_owned(),
                    data: action,
                })
            }
            _ => Err(anyhow::anyhow!(
                "Unknown gRPC client action: {}",
                action_type
            )),
        }
    }
}

fn stream_actions() -> Vec<ActionDefinition> {
    let mut actions = Vec::new();
    for (name, description, example) in [
        ("grpc_stream_start", "Start a real streaming method with a fresh stream_id; server-streaming requires request, client/bidi may provide an initial request", json!({"type":"grpc_stream_start","stream_id":1,"service":"streams.Session","method":"Watch","request":{"name":"watch"}})),
        ("grpc_stream_send", "Queue one typed message on client/bidirectional input; rejects a full queue or closed input", json!({"type":"grpc_stream_send","stream_id":1,"message":{"name":"update","value":2}})),
        ("grpc_stream_finish", "Half-close client/bidirectional input while continuing to receive replies", json!({"type":"grpc_stream_finish","stream_id":1})),
        ("grpc_stream_cancel", "Cancel an active RPC and its pending reads/writes", json!({"type":"grpc_stream_cancel","stream_id":1})),
    ] {
        let mut parameters = vec![Parameter {name:"stream_id".into(),type_hint:"integer".into(),required:true,description:"Positive u32 id, unique for this client session".into()}];
        if name == "grpc_stream_start" {
            for (name,hint,required,description) in [
                ("service","string",true,"Fully qualified service name"), ("method","string",true,"Streaming method name"),
                ("request","object",false,"Typed initial request; required for server-streaming"),
                ("metadata","object",false,"At most 16 lowercase ASCII metadata fields; reserved/binary headers excluded"),
                ("gzip","boolean",false,"Compress outgoing stream messages with gzip"),
            ] {parameters.push(Parameter {name:name.into(),type_hint:hint.into(),required,description:description.into()});}
        } else if name == "grpc_stream_send" {parameters.push(Parameter {name:"message".into(),type_hint:"object".into(),required:true,description:"Field-name JSON matching the request schema, excluding bytes fields".into()});}
        actions.push(ActionDefinition {name:name.into(),description:description.into(),parameters,example,log_template:Some(LogTemplate::new().with_info(format!("gRPC {name} queued for stream {{stream_id}}")))});
    }
    actions
}
fn stream_event(
    name: &'static str,
    description: &'static str,
    fields: &[(&str, &str)],
) -> EventType {
    let mut parameters = vec![Parameter {
        name: "stream_id".into(),
        type_hint: "integer".into(),
        required: true,
        description: "RPC correlation id".into(),
    }];
    parameters.extend(fields.iter().map(|(name, hint)| {
        Parameter {
            name: (*name).into(),
            type_hint: (*hint).into(),
            required: true,
            description: match *name {
                "service" => "Fully qualified protobuf service name",
                "method" => "Streaming RPC method within the declared service",
                "sequence" => "Zero-based sequence of this decoded response",
                "response" => "Decoded response fields matching the protobuf output schema",
                "code" => "Terminal numeric gRPC status code for this RPC",
                "message" => "Terminal gRPC status explanation from the peer",
                "response_count" => "Total decoded responses received before this RPC ended",
                "input_sequence" => "Sequence of the input consumed by the request encoder",
                "queue_capacity" => "Available input queue slot, without a wire delivery receipt",
                _ => "Typed field supplied by the streaming RPC event",
            }
            .into(),
        }
    }));
    EventType::new(name, description, json!({"type":"wait_for_more"}))
        .with_parameters(parameters)
        .with_actions(stream_actions())
}
pub static GRPC_CLIENT_STREAM_OPENED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    stream_event(
        "grpc_stream_opened",
        "Server accepted response headers for this RPC",
        &[("service", "string"), ("method", "string")],
    )
});
pub static GRPC_CLIENT_STREAM_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    stream_event(
        "grpc_stream_message_received",
        "A bounded, decoded typed response arrived",
        &[("sequence", "integer"), ("response", "object")],
    )
});
pub static GRPC_CLIENT_STREAM_ENDED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    stream_event(
        "grpc_stream_ended",
        "RPC completed, failed, reached its deadline or was cancelled",
        &[
            ("code", "integer"),
            ("message", "string"),
            ("response_count", "integer"),
        ],
    )
});
pub static GRPC_CLIENT_STREAM_INPUT_READY_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    stream_event("grpc_stream_input_ready","The request encoder consumed a queued input item; one queue slot is available, without claiming wire delivery",&[("input_sequence","integer"),("queue_capacity","integer")])
});

/// Whether `schema` is a base64-encoded `FileDescriptorSet`, the one form the client loads
/// without `protoc`.
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

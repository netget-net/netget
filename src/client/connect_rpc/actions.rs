use crate::{
    llm::actions::{
        client_trait::{Client, ClientActionResult},
        protocol_trait::Protocol,
        ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
    },
    protocol::{ConnectContext, EventType, LogTemplate},
    state::AppState,
};
use anyhow::{ensure, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
fn field(name: &str, hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: hint.into(),
        description: description.into(),
        required,
    }
}
fn event(name: &str, description: &str, parameters: Vec<Parameter>) -> EventType {
    EventType::new(name, description, json!({"type":"wait_for_more"}))
        .with_parameters(parameters)
        .with_actions(ConnectRpcClientProtocol.get_sync_actions())
}
pub static CONNECTED: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "connect_rpc_connected",
        "Binary ConnectRPC HTTP/1.1 connection ready",
        vec![
            field(
                "remote_addr",
                "string",
                "Connected HTTP/1.1 peer address as host:port",
                true,
            ),
            field("services", "array", "Internal schema's service names", true),
            field(
                "tls_verified",
                "boolean",
                "False for this cleartext binding",
                true,
            ),
        ],
    )
});
pub static OPENED: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "connect_rpc_opened",
        "RPC response headers received",
        vec![
            field("call_id", "integer", "Positive call identifier", true),
            field("service", "string", "Protobuf service", true),
            field("method", "string", "Protobuf method", true),
            field(
                "metadata",
                "object",
                "Bounded ASCII response metadata arrays",
                true,
            ),
            field(
                "server_streaming",
                "boolean",
                "Method returns a stream",
                true,
            ),
        ],
    )
});
pub static MESSAGE: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "connect_rpc_message",
        "Decoded protobuf response with field-name values",
        vec![
            field("call_id", "integer", "Positive call identifier", true),
            field(
                "sequence",
                "integer",
                "Response sequence, starting at 1",
                true,
            ),
            field("response", "object", "Typed response values", true),
        ],
    )
});
pub static ENDED: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "connect_rpc_ended",
        "Validated final status or local RPC failure",
        vec![
            field("call_id", "integer", "Positive call identifier", true),
            field("code", "integer", "gRPC status 0..16", true),
            field("message", "string", "Bounded diagnostic", true),
            field("response_count", "integer", "Decoded response count", true),
            field(
                "metadata",
                "object",
                "Bounded ASCII trailing metadata arrays",
                true,
            ),
        ],
    )
});
#[derive(Default)]
pub struct ConnectRpcClientProtocol;
impl ConnectRpcClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
impl Protocol for ConnectRpcClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "ConnectRPC"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>CONNECT-RPC"
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
    fn description(&self) -> &'static str {
        "Typed binary HTTP/1.1 ConnectRPC unary and server-streaming client"
    }
    fn example_prompt(&self) -> &'static str {
        "Call a ConnectRPC greeting method and read its typed response"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["connect-rpc", "connectrpc", "connect rpc"]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        self.get_sync_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let action = |name: &str, description: &str, parameters: Vec<Parameter>, example: Value| {
            ActionDefinition {
                name: name.into(),
                description: description.into(),
                parameters,
                example,
                log_template: Some(LogTemplate::new().with_info(match name {
                    "connect_rpc_call" => "ConnectRPC call {call_id} queued",
                    "connect_rpc_cancel" => "ConnectRPC call {call_id} cancellation requested",
                    "disconnect" => "ConnectRPC client disconnect requested",
                    "wait_for_more" => "ConnectRPC client waiting for another event",
                    _ => "ConnectRPC client action executed",
                })),
            }
        };
        vec![
            action(
                "connect_rpc_call",
                "Start one unary or server-streaming RPC; only one active RPC per connection",
                vec![
                    field(
                        "call_id",
                        "integer",
                        "Fresh positive u32, never reused within this client; at most 256 calls",
                        true,
                    ),
                    field("service", "string", "Fully qualified service name", true),
                    field(
                        "method",
                        "string",
                        "Method name declared by the selected protobuf service",
                        true,
                    ),
                    field(
                        "request",
                        "object",
                        "Protobuf field-name values; reachable bytes fields are excluded",
                        true,
                    ),
                    field(
                        "metadata",
                        "object",
                        "At most 16 ASCII fields, 8 KiB total; no reserved or binary headers",
                        false,
                    ),
                    field(
                        "gzip",
                        "boolean",
                        "Compress this request; default false",
                        false,
                    ),
                ],
                json!({"type":"connect_rpc_call","call_id":1,"service":"demo.Greeter","method":"Hello","request":{"name":"Ada"}}),
            ),
            action(
                "connect_rpc_cancel",
                "Cancel the matching active RPC and disconnect its HTTP/1.1 connection",
                vec![field("call_id", "integer", "Active call identifier", true)],
                json!({"type":"connect_rpc_cancel","call_id":1}),
            ),
            action(
                "disconnect",
                "Cancel the owned RPC, handlers and transport",
                vec![],
                json!({"type":"disconnect"}),
            ),
            action(
                "wait_for_more",
                "Wait for another event or injected action",
                vec![],
                json!({"type":"wait_for_more"}),
            ),
        ]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED.clone(),
            OPENED.clone(),
            MESSAGE.clone(),
            ENDED.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let mut schema = crate::client::grpc::GrpcClientProtocol::new()
            .get_startup_parameters()
            .into_iter()
            .find(|parameter| parameter.name == "proto_schema")
            .unwrap();
        schema.required = true;
        schema.description = "Required inline .proto, .proto/.pb path or precompiled descriptor set. No reflection; prefer inline schema".into();
        let seconds = |name: &str, description: &str, default: u64| ParameterDefinition {
            name: name.into(),
            type_hint: "integer".into(),
            description: description.into(),
            required: false,
            example: json!(default),
            default: Some(json!(default)),
        };
        vec![
            schema,
            seconds(
                "connect_timeout_secs",
                "Whole schema/TCP/HTTP connection deadline, 1..60 seconds",
                10,
            ),
            seconds(
                "rpc_timeout_secs",
                "Whole RPC deadline including model backpressure, 1..3600 seconds",
                300,
            ),
            seconds(
                "idle_timeout_secs",
                "No RPC or handler activity deadline, 1..3600 seconds",
                120,
            ),
        ]
    }
    fn get_dependencies(&self) -> Vec<crate::protocol::dependencies::ProtocolDependency> {
        crate::server::grpc::actions::GrpcProtocol::new().get_dependencies()
    }
    fn startup_dependencies(
        &self,
        params: Option<&Value>,
    ) -> Vec<crate::protocol::dependencies::ProtocolDependency> {
        crate::server::grpc::actions::GrpcProtocol::new().startup_dependencies(params)
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{DevelopmentState, ProtocolMetadataV2};
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental)
            .implementation("Owned HTTP/1.1 transport with tonic/prost-reflect typed messages and a bounded Connect bare/envelope response and EndStream adapter before tonic decoding.")
            .llm_control("Call, observe typed response messages and final status, cancel or disconnect; one RPC per connection, responsive injected controls.")
            .e2e_testing("Mandatory independent Connect-ES HTTP/1.1 server, paired NetGet binding and malformed framing/deadline/lifecycle tests.")
            .notes("Binary protobuf only, cleartext only. JSON message codecs, GET, client/bidirectional streaming, reflection, WebSocket, automatic retries/reconnect, TLS, browser execution and pcap/fuzz evidence are excluded. Cancellation disconnects the HTTP/1.1 session.")
            .max_inbound_bytes(crate::server::connect_rpc::wire::MAX_MESSAGE_BYTES).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let schema = "syntax=\"proto3\"; package demo; message Greeting { string name=1; } service Greeter { rpc Hello(Greeting) returns (Greeting); }";
        let call = json!({"type":"connect_rpc_call","call_id":1,"service":"demo.Greeter","method":"Hello","request":{"name":"Ada"}});
        let base = |handler: Option<Value>, instruction: &str| {
            let mut value = json!({"type":"open_client","base_stack":"connect-rpc","remote_addr":"127.0.0.1:8080","startup_params":{"proto_schema":schema},"instruction":instruction});
            if let Some(handler) = handler {
                value["event_handlers"] =
                    json!([{"event_pattern":"connect_rpc_connected","handler":handler}]);
            }
            value
        };
        StartupExamples::new(
            base(None,"Call demo.Greeter.Hello with call_id1 and request.name Ada, then wait for its messages and final status."),
            base(Some(json!({"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'connect_rpc_call','call_id':1,'service':'demo.Greeter','method':'Hello','request':{'name':'Ada'}}]}))"})),""),
            base(Some(json!({"type":"static","actions":[call]})),""),
        )
    }
}
impl Client for ConnectRpcClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::ConnectRpcClient::connect(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        let kind = action["type"].as_str().unwrap_or("");
        match kind {
            "disconnect" => Ok(ClientActionResult::Disconnect),
            "wait_for_more" => Ok(ClientActionResult::WaitForMore),
            "connect_rpc_call" | "connect_rpc_cancel" => {
                ensure!(
                    action["call_id"]
                        .as_u64()
                        .is_some_and(|id| id > 0 && id <= u64::from(u32::MAX)),
                    "call_id must be a positive u32"
                );
                if kind == "connect_rpc_call" {
                    for (key, limit) in [("service", 1024), ("method", 256)] {
                        ensure!(
                            action[key]
                                .as_str()
                                .is_some_and(|value| !value.is_empty() && value.len() <= limit),
                            "invalid {key}"
                        );
                    }
                    ensure!(action["request"].is_object(), "request must be an object");
                    ensure!(
                        action.get("gzip").is_none_or(Value::is_boolean),
                        "gzip must be boolean"
                    );
                }
                Ok(ClientActionResult::Custom {
                    name: kind.into(),
                    data: action,
                })
            }
            _ => anyhow::bail!("unknown ConnectRPC action"),
        }
    }
}

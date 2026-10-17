use crate::{
    llm::actions::{
        protocol_trait::{ActionResult, Protocol, Server},
        ActionDefinition, ParameterDefinition, StartupExamples,
    },
    protocol::{EventType, SpawnContext},
    state::AppState,
};
use anyhow::Result;
use serde_json::{json, Value};
#[derive(Default)]
pub struct GrpcWebProtocol;
impl GrpcWebProtocol {
    pub fn new() -> Self {
        Self
    }
}
impl Protocol for GrpcWebProtocol {
    fn protocol_name(&self) -> &'static str {
        "gRPC-Web"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP>GRPC-WEB"
    }
    fn group_name(&self) -> &'static str {
        "Application"
    }
    fn description(&self) -> &'static str {
        "Binary protobuf HTTP/1.1 unary and server-streaming binding"
    }
    fn example_prompt(&self) -> &'static str {
        "Serve a protobuf greeting to a gRPC-Web client"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["grpc-web", "grpcweb", "grpc web"]
    }
    fn get_async_actions(&self, state: &AppState) -> Vec<ActionDefinition> {
        crate::server::grpc::actions::GrpcProtocol::new().get_async_actions(state)
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        crate::server::grpc::actions::GrpcProtocol::new()
            .get_sync_actions()
            .into_iter()
            .filter(|action| action.name != "grpc_unary_response")
            .collect()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        crate::server::grpc::actions::GrpcProtocol::new()
            .get_event_types()
            .into_iter()
            .filter(|event| matches!(event.id.as_str(), "grpc_stream_opened" | "grpc_stream_tick"))
            .collect()
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let mut parameters =
            crate::server::grpc::actions::GrpcProtocol::new().get_startup_parameters();
        parameters.retain(|parameter| parameter.name == "proto_schema");
        parameters.extend([
            ParameterDefinition { name:"rpc_timeout_secs".into(), type_hint:"integer".into(), required:false,
                description:"Whole RPC deadline 1..3600 seconds, shortened by grpc-timeout; includes response backpressure".into(),
                example:json!(300), default:Some(json!(super::DEFAULT_RPC_TIMEOUT_SECS)) },
            ParameterDefinition { name:"allow_origin".into(), type_hint:"string".into(), required:false,
                description:"One exact HTTP(S) browser origin, without trailing slash; omitted rejects all Origin headers. No credentials or wildcard".into(),
                example:json!("https://app.example"), default:None },
        ]);
        parameters
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
            .implementation("Separately registered binary protobuf gRPC-Web over HTTP/1.1. tonic-web0.12.3 frames responses; tonic0.12.3 and shared bounded DynamicCodec decode messages.")
            .llm_control("Typed stream-open and tick events for unary and server-streaming methods; explicit send/finish/cancel/wait/error. No application storage.")
            .e2e_testing("Mandatory pinned independent Connect-ES peers in both roles, NetGet pairs and bounded framing/cancellation tests.")
            .notes("Binary only: text mode is rejected. Client streaming, bidi, reflection, WebSocket, receiver TLS, browser execution, pcap and fuzz evidence are outside this Experimental scope. CORS requires one explicitly configured origin; no credentials.")
            .max_inbound_bytes(super::wire::MAX_MESSAGE_BYTES + 5).history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let schema = "syntax=\"proto3\"; package demo; message Greeting { string name=1; } service Greeter { rpc Hello(Greeting) returns (Greeting); }";
        let base = |handler: Option<Value>, instruction: &str| {
            let mut value = json!({"type":"open_server","base_stack":"grpc-web","port":8080,"startup_params":{"proto_schema":schema},"instruction":instruction});
            if let Some(handler) = handler {
                value["event_handlers"] =
                    json!([{"event_pattern":"grpc_stream_opened","handler":handler}]);
            }
            value
        };
        StartupExamples::new(
            base(None, "On grpc_stream_opened, greet the request's message.name using grpc_stream_send with message.name, then grpc_stream_finish."),
            base(Some(json!({"type":"script","language":"python","code":"import json,sys\ne=json.load(sys.stdin)['event']\nprint(json.dumps({'actions':[{'type':'grpc_stream_send','message':{'name':'Hello '+e['message']['name']}},{'type':'grpc_stream_finish'}]}))"})), ""),
            base(Some(json!({"type":"static","actions":[{"type":"grpc_stream_send","message":{"name":"Hello"}},{"type":"grpc_stream_finish"}]})), ""),
        )
    }
}
impl Server for GrpcWebProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::GrpcWebServer::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        anyhow::ensure!(
            action["type"] != "grpc_unary_response",
            "use grpc_stream_send and grpc_stream_finish for gRPC-Web unary replies"
        );
        crate::server::grpc::actions::GrpcProtocol::new().execute_action(action)
    }
}

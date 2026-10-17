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
pub static OPENED: std::sync::LazyLock<EventType> =
    std::sync::LazyLock::new(|| connect_event("grpc_stream_opened"));
pub static TICK: std::sync::LazyLock<EventType> =
    std::sync::LazyLock::new(|| connect_event("grpc_stream_tick"));
fn connect_event(id: &str) -> EventType {
    let mut event = crate::server::grpc::actions::GrpcProtocol::new()
        .get_event_types()
        .into_iter()
        .find(|event| event.id == id)
        .unwrap();
    event.parameters.push(crate::llm::actions::Parameter {
        name: "metadata".into(),
        type_hint: "object".into(),
        description: "Bounded ASCII request metadata arrays".into(),
        required: true,
    });
    event.with_actions(ConnectRpcProtocol.get_sync_actions())
}
pub(crate) fn event_type(id: &str) -> Option<&'static EventType> {
    match id {
        "grpc_stream_opened" => Some(&OPENED),
        "grpc_stream_tick" => Some(&TICK),
        _ => None,
    }
}
#[derive(Default)]
pub struct ConnectRpcProtocol;
impl ConnectRpcProtocol {
    pub fn new() -> Self {
        Self
    }
}
impl Protocol for ConnectRpcProtocol {
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
        "Binary protobuf HTTP/1.1 unary and server-streaming binding"
    }
    fn example_prompt(&self) -> &'static str {
        "Serve a protobuf greeting to a ConnectRPC client"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["connect-rpc", "connectrpc", "connect rpc"]
    }
    fn get_async_actions(&self, state: &AppState) -> Vec<ActionDefinition> {
        crate::server::grpc::actions::GrpcProtocol::new().get_async_actions(state)
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        crate::server::grpc::actions::GrpcProtocol::new()
            .get_sync_actions()
            .into_iter()
            .filter(|action| action.name != "grpc_unary_response")
            .chain(std::iter::once(super::wire::metadata_action()))
            .collect()
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![OPENED.clone(), TICK.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        let mut parameters =
            crate::server::grpc::actions::GrpcProtocol::new().get_startup_parameters();
        parameters.retain(|parameter| parameter.name == "proto_schema");
        parameters.extend([
            ParameterDefinition { name:"rpc_timeout_secs".into(), type_hint:"integer".into(), required:false,
                description:"Whole RPC deadline 1..3600 seconds, shortened by connect-timeout-ms; includes response backpressure".into(),
                example:json!(super::DEFAULT_RPC_TIMEOUT_SECS), default:Some(json!(super::DEFAULT_RPC_TIMEOUT_SECS)) },
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
            .implementation("Separately registered binary protobuf ConnectRPC over HTTP/1.1. Connect bare/envelope framing and errors adapt tonic0.12.3 and shared bounded DynamicCodec decode messages.")
            .llm_control("Typed stream-open and tick events for unary and server-streaming methods; explicit send/finish/cancel/wait/error. No application storage.")
            .e2e_testing("Mandatory pinned independent Connect-ES peers in both roles, NetGet pairs and bounded framing/cancellation tests.")
            .notes("Binary protobuf only: JSON message codecs and GET are rejected. Client streaming, bidi, reflection, WebSocket, receiver TLS, browser execution, pcap and fuzz evidence are outside this Experimental scope. Origin requests are rejected; no browser or CORS claim.")
            .max_inbound_bytes(super::wire::MAX_MESSAGE_BYTES + 5).history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let schema = "syntax=\"proto3\"; package demo; message Greeting { string name=1; } service Greeter { rpc Hello(Greeting) returns (Greeting); }";
        let base = |handler: Option<Value>, instruction: &str| {
            let mut value = json!({"type":"open_server","base_stack":"connect-rpc","port":8080,"startup_params":{"proto_schema":schema},"instruction":instruction});
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
impl Server for ConnectRpcProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::ConnectRpcServer::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        if action["type"] == "connect_rpc_metadata" {
            super::wire::validate_metadata_action(&action)?;
            return Ok(ActionResult::Custom {
                name: "connect_rpc_metadata".into(),
                data: action,
            });
        }
        anyhow::ensure!(
            action["type"] != "grpc_unary_response",
            "use grpc_stream_send and grpc_stream_finish for ConnectRPC unary replies"
        );
        crate::server::grpc::actions::GrpcProtocol::new().execute_action(action)
    }
}

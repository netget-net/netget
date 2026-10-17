use crate::server::gnmi::actions::{definition, field};
use crate::{
    llm::actions::{
        client_trait::{Client, ClientActionResult},
        protocol_trait::Protocol,
        ActionDefinition, ParameterDefinition, StartupExamples,
    },
    protocol::{ConnectContext, EventType, LogTemplate},
    state::AppState,
};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct GnmiClientProtocol;
impl GnmiClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
fn event(
    name: &str,
    description: &str,
    parameters: Vec<crate::llm::actions::Parameter>,
) -> EventType {
    EventType::new(name, description, json!({"type":"wait_for_more"}))
        .with_parameters(parameters)
        .with_actions(GnmiClientProtocol.get_sync_actions())
}
pub static CONNECTED: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "gnmi_client_connected",
        "HTTP/2 gNMI connection ready",
        vec![
            field("remote_addr", "string", "Connected endpoint", true),
            field(
                "tls_verified",
                "boolean",
                "Certificate and server name verified when true",
                true,
            ),
        ],
    )
});
pub static RESPONSE: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "gnmi_client_response",
        "Validated typed Capabilities/Get/Set response",
        vec![
            field("call_id", "integer", "Originating call", true),
            field(
                "method",
                "string",
                "Completed Capabilities, Get or Set RPC name",
                true,
            ),
            field("response", "object", "Decoded typed result", true),
        ],
    )
});
pub static UPDATE: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "gnmi_client_update",
        "Validated subscription notification",
        vec![
            field("call_id", "integer", "Originating subscription", true),
            field(
                "sequence",
                "integer",
                "Response sequence from 1, including sync",
                true,
            ),
            field("notification", "object", "Typed paths and values", true),
        ],
    )
});
pub static SYNC: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "gnmi_client_sync",
        "Initial/POLL snapshot complete",
        vec![
            field("call_id", "integer", "Originating subscription", true),
            field("sequence", "integer", "Response sequence from 1", true),
        ],
    )
});
pub static ENDED: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "gnmi_client_ended",
        "Final gRPC status or local bounded failure",
        vec![
            field("call_id", "integer", "Originating call", true),
            field("code", "integer", "gRPC status 0..16", true),
            field("message", "string", "Diagnostic, at most 512 bytes", true),
            field(
                "response_count",
                "integer",
                "Validated response messages",
                true,
            ),
        ],
    )
});
impl Protocol for GnmiClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "gNMI"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>HTTP2>GRPC>GNMI"
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
    fn description(&self) -> &'static str {
        "Typed OpenConfig gNMI RPC and subscription client"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["gnmi", "openconfig"]
    }
    fn example_prompt(&self) -> &'static str {
        "Read typed gNMI state and cancel a live subscription"
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        let mut m = crate::llm::actions::protocol_trait::Protocol::metadata(
            &crate::server::gnmi::actions::GnmiProtocol,
        );
        // The server's metadata says what the gNMI target declares; a client is one session
        // pursuing one instruction, so it keeps its history like every other client.
        m.history = crate::protocol::metadata::HistoryMode::Last(
            crate::protocol::metadata::SESSION_HISTORY_ENTRIES,
        );
        m.batching = crate::protocol::metadata::BatchingMode::Unsupported;
        m.notes=Some("Experimental typed gNMI client; Capabilities/Get/Set and ONCE/POLL/STREAM, TLS certificate/name verification with optional bounded CA, explicit cleartext local-fixture mode. No automatic reconnect/retry; no opaque values, extensions, SAMPLE, YANG execution, storage, authentication, reflection, fuzz or pcap evidence.".into());
        m
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED.clone(),
            RESPONSE.clone(),
            UPDATE.clone(),
            SYNC.clone(),
            ENDED.clone(),
        ]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            definition(
                "use_tls",
                "boolean",
                "Verify certificate and server name; false explicitly selects cleartext fixtures",
                Some(json!(super::DEFAULT_TLS)),
            ),
            definition(
                "server_name",
                "string",
                "TLS certificate name override, at most 253 bytes; requires use_tls",
                None,
            ),
            definition(
                "ca_file",
                "string",
                "Additional trusted CA PEM regular file, at most 1 MiB; requires use_tls",
                None,
            ),
            definition(
                "connect_timeout_secs",
                "integer",
                "Whole file/TCP/TLS/HTTP2 startup deadline, 1..60 seconds",
                Some(json!(super::CONNECT_TIMEOUT_SECS)),
            ),
            definition(
                "rpc_timeout_secs",
                "integer",
                "Whole RPC including stream/event backpressure, 1..3600 seconds",
                Some(json!(crate::server::gnmi::DEFAULT_RPC_TIMEOUT_SECS)),
            ),
            definition(
                "idle_timeout_secs",
                "integer",
                "Idle connection closes after 1..3600 seconds, only with no RPC/handler",
                Some(json!(super::DEFAULT_IDLE_TIMEOUT_SECS)),
            ),
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        self.get_sync_actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let action = |name: &str, description: &str, request: Option<&str>, example: Value| {
            let mut parameters = vec![];
            if name != "wait_for_more" && name != "disconnect" {
                parameters.push(field(
                    "call_id",
                    "integer",
                    "Fresh positive u32 for RPCs, active ID for controls; at most 256 total calls",
                    true,
                ));
            }
            if let Some(request) = request {
                parameters.push(field("request", "object", request, true));
            }
            if matches!(
                name,
                "gnmi_capabilities" | "gnmi_get" | "gnmi_set" | "gnmi_subscribe"
            ) {
                parameters.push(field(
                    "gzip",
                    "boolean",
                    "Compress request and accept bounded gzip responses",
                    false,
                ));
            }
            ActionDefinition {
                name: name.into(),
                description: description.into(),
                parameters,
                example,
                log_template: Some(LogTemplate::new().with_info(match name {
                    "gnmi_capabilities" => "gNMI Capabilities call {call_id} queued",
                    "gnmi_get" => "gNMI Get call {call_id} queued",
                    "gnmi_set" => "gNMI Set call {call_id} queued",
                    "gnmi_subscribe" => "gNMI Subscribe call {call_id} queued",
                    "gnmi_poll" => "gNMI Poll for call {call_id} queued",
                    "gnmi_cancel" => "gNMI call {call_id} cancellation requested",
                    "disconnect" => "gNMI client disconnect requested",
                    _ => "gNMI client waiting for another event",
                })),
            }
        };
        vec![
            action("gnmi_capabilities","Read capabilities",None,json!({"type":"gnmi_capabilities","call_id":1})),
            action("gnmi_get","Read typed state snapshot",Some("{prefix,path:[{origin,target,elem:[{name,key}]}],data_type:ALL|CONFIG|STATE|OPERATIONAL,encoding:PROTO|JSON|JSON_IETF|ASCII,use_models}"),json!({"type":"gnmi_get","call_id":1,"request":{"path":[{"elem":[{"name":"system"}]}],"encoding":"PROTO"}})),
            action("gnmi_set","Send one atomic delete/replace/update request",Some("{prefix,delete:[path],replace:[{path,value:{kind,value},duplicates}],update:[...]} ; signed/unsigned integers are decimal strings"),json!({"type":"gnmi_set","call_id":1,"request":{"delete":[{"elem":[{"name":"old"}]}]}})),
            action("gnmi_subscribe","Start a bounded ONCE/POLL/STREAM subscription",Some("{prefix,mode:ONCE|POLL|STREAM,subscription:[{path,mode:TARGET_DEFINED|ON_CHANGE}],encoding,updates_only,use_models}"),json!({"type":"gnmi_subscribe","call_id":1,"request":{"mode":"ONCE","subscription":[{"path":{"elem":[{"name":"system"}]}}],"encoding":"PROTO"}})),
            action("gnmi_poll","Request next POLL snapshot after prior sync",None,json!({"type":"gnmi_poll","call_id":1})),
            action("gnmi_cancel","Cancel an active RPC responsively",None,json!({"type":"gnmi_cancel","call_id":1})),
            action("wait_for_more","Leave the owned connection running",None,json!({"type":"wait_for_more"})),
            action("disconnect","Drop the owned socket and all calls/handlers",None,json!({"type":"disconnect"})),
        ]
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let answer = json!({"type":"gnmi_capabilities","call_id":1});
        let base = |handler: Option<Value>, instruction: &str| {
            let mut v = json!({"type":"open_client","base_stack":"gnmi","remote_addr":"127.0.0.1:9339","instruction":instruction});
            if let Some(handler) = handler {
                v["event_handlers"] =
                    json!([{"event_pattern":"gnmi_client_connected","handler":handler}]);
            }
            v
        };
        StartupExamples::new(
            base(
                None,
                "Send gnmi_capabilities with call_id1, then wait for the typed response.",
            ),
            base(
                Some(
                    json!({"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'gnmi_capabilities','call_id':1}]}))"}),
                ),
                "",
            ),
            base(Some(json!({"type":"static","actions":[answer]})), ""),
        )
    }
}
impl Client for GnmiClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, action: Value) -> anyhow::Result<ClientActionResult> {
        super::request::parse(&action)?;
        Ok(match action["type"].as_str() {
            Some("disconnect") => ClientActionResult::Disconnect,
            Some("wait_for_more") => ClientActionResult::WaitForMore,
            _ => ClientActionResult::Custom {
                name: "gnmi_command".into(),
                data: action,
            },
        })
    }
}

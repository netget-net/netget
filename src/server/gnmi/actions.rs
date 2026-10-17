use crate::{
    llm::actions::{
        protocol_trait::{ActionResult, Protocol, Server},
        ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
    },
    protocol::{EventType, LogTemplate, SpawnContext},
    state::AppState,
};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct GnmiProtocol;
impl GnmiProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn field(name: &str, hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: hint.into(),
        description: description.into(),
        required,
    }
}
pub fn definition(
    name: &str,
    hint: &str,
    description: &str,
    default: Option<Value>,
) -> ParameterDefinition {
    ParameterDefinition {
        name: name.into(),
        type_hint: hint.into(),
        description: description.into(),
        required: false,
        example: default.clone().unwrap_or_else(|| {
            if name == "server_name" {
                json!("localhost")
            } else {
                json!("/path/to/file.pem")
            }
        }),
        default,
    }
}
fn event(name: &str, description: &str) -> EventType {
    EventType::new(
        name,
        description,
        json!({"type":"gnmi_error","code":12,"message":"unsupported request"}),
    )
    .with_parameters(vec![
        field(
            "request",
            "object",
            "Typed paths, values and options; never encoded protobuf",
            true,
        ),
        field(
            "rpc_id",
            "integer",
            "Receiver-local RPC identifier assigned at admission",
            true,
        ),
    ])
    .with_actions(GnmiProtocol.get_sync_actions())
}
pub static CAPABILITIES: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "gnmi_capabilities_request",
        "Choose advertised models and selected encodings; gnmi_version is fixed at 0.10.0",
    )
});
pub static GET: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "gnmi_get_request",
        "Return snapshot notifications matching the requested encoding",
    )
});
pub static SET: LazyLock<EventType> = LazyLock::new(|| {
    event("gnmi_set_request","Approve the entire delete/replace/update transaction or return one gRPC error; no configuration is stored")
});
pub static SUBSCRIBE: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "gnmi_subscribe_request",
        "Initial subscription cycle: updates then exactly one sync; ONCE closes after sync",
    )
});
pub static POLL: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "gnmi_poll_request",
        "POLL requested a new snapshot: updates then exactly one sync",
    )
});
pub static TICK: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "gnmi_subscription_tick",
        "STREAM update opportunity requested by gnmi_wait; send updates, wait or finish",
    )
});
impl Protocol for GnmiProtocol {
    fn default_binding(&self) -> Option<crate::protocol::BindingDefaults> {
        Some(crate::protocol::BindingDefaults::port_based(
            "127.0.0.1",
            super::DEFAULT_PORT,
        ))
    }
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
        "Typed OpenConfig gNMI RPC and subscription receiver"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["gnmi", "openconfig"]
    }
    fn example_prompt(&self) -> &'static str {
        "Serve gNMI snapshots and acknowledge configuration transactions without storing device data"
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CAPABILITIES.clone(),
            GET.clone(),
            SET.clone(),
            SUBSCRIBE.clone(),
            POLL.clone(),
            TICK.clone(),
        ]
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            definition(
                "use_tls",
                "boolean",
                "TLS receiver; requires cert_file and key_file",
                Some(json!(super::DEFAULT_TLS)),
            ),
            definition(
                "cert_file",
                "string",
                "Bounded regular PEM certificate file, at most 1 MiB",
                None,
            ),
            definition(
                "key_file",
                "string",
                "Bounded regular PEM private key file, at most 1 MiB",
                None,
            ),
            definition(
                "rpc_timeout_secs",
                "integer",
                "Whole unary/subscription deadline, 1..3600 seconds; grpc-timeout can shorten it",
                Some(json!(super::DEFAULT_RPC_TIMEOUT_SECS)),
            ),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::{
            DevelopmentState, PrivilegeRequirement, ProtocolMetadataV2,
        };
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None)
            .implementation("Pinned OpenConfig gNMI v0.14.1 schema; tonic HTTP/2 Capabilities/Get/Set and ONCE/POLL/STREAM Subscribe with bounded structural decoding before prost allocation")
            .llm_control("Advertised models/encodings, typed snapshot notifications, transaction-wide Set acknowledgement, stream updates/sync/wait/finish and explicit gRPC errors; no device datastore")
            .e2e_testing("Mandatory pinned gNMIc 0.49.0 and public generated SDK peers, both roles and native pairing; see tests/server/gnmi/AGENTS.md for measured coverage")
            .notes("Experimental selected subset: structured Path.elem, scalar/leaf-list/JSON/JSON_IETF/ASCII values, TARGET_DEFINED/ON_CHANGE stream control. Opaque bytes/Any, deprecated paths/values/errors, extensions, union_replace, SAMPLE/heartbeat/suppression/nonzero QoS/aggregation, authentication, reflection, YANG execution, storage, fuzz and pcap conformance are excluded. TLS requires explicit bounded PEM inputs; cleartext is explicit default for local fixtures.")
            .well_known_port(9339)
            .max_inbound_bytes(super::codec::MAX_MESSAGE_BYTES).answers_on_failure()
            .request_only("gNMI updates belong to an established Subscribe RPC; no unprompted connection-level messages")
            .history(crate::protocol::metadata::HistoryMode::Off)
            .batching(crate::protocol::metadata::BatchingMode::Unsupported)
            .build()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        let action = |name: &str, description: &str, parameters: Vec<Parameter>, example: Value| {
            ActionDefinition {
                name: name.into(),
                description: description.into(),
                parameters,
                example,
                log_template: Some(LogTemplate::new().with_info(match name {
                    "gnmi_capabilities" => "gNMI Capabilities response selected",
                    "gnmi_get_response" => "gNMI Get snapshot selected",
                    "gnmi_set_accepted" => "gNMI Set transaction accepted",
                    "gnmi_update" => "gNMI subscription updates selected",
                    "gnmi_sync" => "gNMI subscription snapshot synced",
                    "gnmi_wait" => "gNMI subscription wait selected",
                    "gnmi_finish" => "gNMI subscription finish selected",
                    _ => "gNMI RPC rejected with status {code}",
                })),
            }
        };
        vec![
            action("gnmi_capabilities","Reply with selected capabilities",vec![field("supported_models","array","Up to 128 {name,organization,version} models",true),field("supported_encodings","array","1..4 of JSON,PROTO,ASCII,JSON_IETF; BYTES is excluded",true)],json!({"type":"gnmi_capabilities","supported_models":[],"supported_encodings":["PROTO"]})),
            action("gnmi_get_response","Return up to 128 typed notifications",vec![field("notification","array","{timestamp: decimal string,prefix:{origin,target,elem:[{name,key}]},update:[{path,value:{kind,value},duplicates}],delete,atomic}",true)],json!({"type":"gnmi_get_response","notification":[]})),
            action("gnmi_set_accepted","Acknowledge every operation in the request in delete/replace/update order; no data is retained",vec![field("timestamp","string","i64 nanoseconds since epoch, as decimal string",true)],json!({"type":"gnmi_set_accepted","timestamp":"1"})),
            action("gnmi_update","Send bounded typed notifications within the subscription",vec![field("notification","array","Same typed notification structure as gnmi_get_response; matches requested encoding",true)],json!({"type":"gnmi_update","notification":[]})),
            action("gnmi_sync","Mark the current initial/POLL snapshot complete; ONCE then closes",vec![],json!({"type":"gnmi_sync"})),
            action("gnmi_wait","Request another STREAM handler tick; permitted only after initial sync",vec![field("milliseconds","integer","1..1000 milliseconds",true)],json!({"type":"gnmi_wait","milliseconds":1000})),
            action("gnmi_finish","End a STREAM after its initial sync",vec![],json!({"type":"gnmi_finish"})),
            action("gnmi_error","Reject the RPC without an invented success",vec![field("code","integer","Nonzero gRPC status 1..16",true),field("message","string","At most 512 bytes",true)],json!({"type":"gnmi_error","code":7,"message":"denied"})),
        ]
    }
    fn get_startup_examples(&self) -> StartupExamples {
        let answer = json!({"type":"gnmi_capabilities","supported_models":[],"supported_encodings":["PROTO"]});
        let base = |handler: Option<Value>, instruction: &str| {
            let mut v = json!({"type":"open_server","base_stack":"gnmi","port":0,"instruction":instruction});
            if let Some(handler) = handler {
                v["event_handlers"] =
                    json!([{"event_pattern":"gnmi_capabilities_request","handler":handler}]);
            }
            v
        };
        StartupExamples::new(base(None,"Answer Capabilities with no models and PROTO encoding; reject other RPCs with code12."),base(Some(json!({"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'gnmi_capabilities','supported_models':[],'supported_encodings':['PROTO']}]}))"})),""),base(Some(json!({"type":"static","actions":[answer]})),""))
    }
}
impl Server for GnmiProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<std::net::SocketAddr>> + Send>,
    > {
        Box::pin(super::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> anyhow::Result<ActionResult> {
        super::semantic::check_model(&action)?;
        super::semantic::answer(&action)?;
        Ok(ActionResult::Custom {
            name: "gnmi_answer".into(),
            data: action,
        })
    }
}

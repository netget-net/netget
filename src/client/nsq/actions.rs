use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, Parameter,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{ConnectContext, EventType};
use crate::state::app_state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct NsqClientProtocol;
impl NsqClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
fn p(name: &str, kind: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: kind.into(),
        description: description.into(),
        required,
    }
}
fn request() -> ActionDefinition {
    ActionDefinition{name:"nsq_request".into(),description:"Send a typed NSQ command; replies and messages are separate events. RDY is the maximum simultaneous in-flight messages, replenished by FIN/REQ.".into(),parameters:vec![
        p("operation","string","publish/publish_many/publish_deferred/subscribe/ready/finish/requeue/touch/close/nop",true),
        p("topic","string","NSQ topic (1..64 ASCII name characters, optional #ephemeral)",false),
        p("channel","string","Subscription channel",false),
        p("body","string","Nonempty UTF-8 message, at most 1 MiB",false),
        p("messages","array","1..1024 UTF-8 messages for publish_many; combined wire body at most 5 MiB",false),
        p("message_id","string","16 hexadecimal characters from nsq_message",false),
        p("count","integer","RDY simultaneous in-flight limit 0..2500, default 1; 0 pauses deliveries",false),
        p("delay_ms","integer","DPUB/REQ delay 0..3600000 ms, default 0",false),
    ],example:json!({"type":"nsq_request","operation":"publish","topic":"greetings","body":"hello"}),log_template: Some(LogTemplate::new().with_info("-> NSQ {operation}"))}
}
fn disconnect() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".into(),
        description: "Immediately close NSQ, including a stalled exchange".into(),
        parameters: vec![],
        example: json!({"type":"disconnect"}),
        log_template: Some(LogTemplate::new().with_info("-> NSQ disconnect")),
    }
}
fn actions() -> Vec<ActionDefinition> {
    vec![request(), disconnect()]
}
fn event(id: &str, description: &str, parameters: Vec<Parameter>) -> EventType {
    EventType::new(id, description, request().example)
        .with_parameters(parameters)
        .with_actions(actions())
}
pub static CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "nsq_connected",
        "IDENTIFY completed; features negotiated. Publish or subscribe then set ready.",
        vec![
            p(
                "remote_addr",
                "string",
                "Remote IP and TCP port of the NSQ broker",
                true,
            ),
            p("features", "object", "Validated negotiation response", true),
        ],
    )
});
pub static RESPONSE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event(
        "nsq_response",
        "A complete command response. Commands FIN/REQ/TOUCH/RDY/NOP have no success response.",
        vec![
            p("request", "object", "Typed originating request", true),
            p(
                "command",
                "string",
                "NSQ wire command that produced this response",
                true,
            ),
            p("status", "string", "OK or CLOSE_WAIT", true),
        ],
    )
});
pub static MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("nsq_message","A delivered message; finish, requeue or touch using message_id. No automatic acknowledgement.",vec![p("topic","string","Subscribed topic",true),p("channel","string","Subscribed channel",true),p("message_id","string","16-character message ID",true),p("timestamp_ns","integer","Unix nanoseconds",true),p("attempts","integer","Delivery attempts",true),p("body","string","UTF-8 text (null when not UTF-8)",false),p("body_bytes","integer","Exact byte length",true),p("body_utf8","boolean","Whether body decoded as UTF-8",true)])
});
pub static ERROR_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    event("nsq_error","A protocol refusal. Fatal errors end the connection; FIN/REQ/TOUCH failures are recoverable.",vec![p("code","string","NSQ protocol error code from the broker",true),p("description","string","Broker explanation of the refused command",true),p("fatal","boolean","Whether connection is closing",true),p("request","object","Pending response-producing request, if any; asynchronous errors may be uncorrelated",false)])
});
impl Protocol for NsqClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "NSQ"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>TCP>NSQ"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["nsq", "nsqd", "pubsub", "queue"]
    }
    fn description(&self) -> &'static str {
        "NSQ V2 publisher and subscriber with explicit delivery acknowledgements"
    }
    fn example_prompt(&self) -> &'static str {
        "Connect to NSQ on localhost:4150 and publish hello to greetings"
    }
    fn group_name(&self) -> &'static str {
        "Messaging"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        actions()
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![
            CONNECTED_EVENT.clone(),
            RESPONSE_EVENT.clone(),
            MESSAGE_EVENT.clone(),
            ERROR_EVENT.clone(),
        ]
    }
    fn metadata(&self) -> crate::protocol::metadata::ProtocolMetadataV2 {
        use crate::protocol::metadata::*;
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).privilege_requirement(PrivilegeRequirement::None).well_known_port(4150)
        .implementation("Tokio TCP V2; automatic IDENTIFY, bounded complete frames and independent heartbeat handling")
        .llm_control("PUB/MPUB/DPUB, SUB/RDY, FIN/REQ/TOUCH, CLS; structured responses, deliveries and refusals")
        .e2e_testing("Independent nsqd 1.3.0 daemon lifecycle, RDY concurrency, publish/consume/requeue/touch; NetGet pair and negative/lifecycle tests")
        .notes("Plain TCP only. Authentication-required, TLS or compression negotiation is refused explicitly. No lookupd/discovery, reconnect, automatic FIN, binary outbound payloads or persistent queue. UTF-8 inbound body is null for binary messages, with exact byte count. MPUB at most 1024 messages. Response/partial-frame/write deadline 15s, event and action queues 16, handler followups 4; fresh deliveries reset followup depth. All three tasks tracked; command handle available before IDENTIFY and manual events.")
        .max_inbound_bytes(crate::server::nsq::wire::MAX_FRAME_DATA).history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_parameters(&self) -> Vec<crate::llm::actions::ParameterDefinition> {
        vec![crate::llm::actions::ParameterDefinition {
            name: "heartbeat_interval_ms".into(),
            type_hint: "integer".into(),
            description: "Heartbeat interval 1000..60000 ms; replies run independently of handlers"
                .into(),
            required: false,
            example: json!(1000),
            default: Some(json!(super::DEFAULT_HEARTBEAT_MS)),
        }]
    }
    fn get_startup_examples(&self) -> crate::llm::actions::StartupExamples {
        let llm = json!({"protocol":"nsq","remote_addr":"127.0.0.1:4150","instruction":"Publish hello to greetings"});
        let mut static_example = llm.clone();
        static_example["event_handlers"] = json!([{"event_pattern":"nsq_connected","handler":{"type":"static","actions":[request().example]}},{"event_pattern":"*","handler":{"type":"static","actions":[]}}]);
        let mut scripted = static_example.clone();
        scripted["event_handlers"][0]["handler"] = json!({"type":"script","language":"python","code":"import json, sys\njson.dump({'actions':[{'type':'nsq_request','operation':'publish','topic':'greetings','body':'hello'}]}, sys.stdout)"});
        crate::llm::actions::StartupExamples::new(llm, scripted, static_example)
    }
}
impl Client for NsqClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::connect(ctx))
    }
    fn execute_action(&self, v: Value) -> Result<ClientActionResult> {
        match v["type"].as_str() {
            Some("nsq_request") => {
                super::wire::request(&v)?;
                Ok(ClientActionResult::Custom {
                    name: "nsq_request".into(),
                    data: v,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("Unknown NSQ client action"),
        }
    }
}

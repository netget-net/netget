use crate::llm::actions::{
    client_trait::{Client, ClientActionResult},
    protocol_trait::Protocol,
    ActionDefinition, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{
    metadata::{DevelopmentState, ProtocolMetadataV2},
    ConnectContext, EventType,
};
use crate::server::gelf::{
    actions::{parameter, transport_parameter},
    codec::{self, Message, DEFAULT_CHUNK_SIZE, DEFAULT_COMPRESSION},
};
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct GelfClientProtocol;
impl GelfClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn send_action() -> ActionDefinition {
    ActionDefinition {name:"send_gelf_message".into(),description:"Emit one structured GELF 1.1 log. Entire message/compression/chunk plan is validated before writing. Local acceptance does not confirm collector persistence; no automatic retries.".into(),parameters:vec![parameter("message","object","host and short_message required; optional full_message, finite nonnegative timestamp, level 0..7, facility/file/line, additional_fields object with unprefixed names and string/number values. id prohibited. Encoded JSON <=256KiB; UDP requires <=128 chunks.",true)],example:json!({"type":"send_gelf_message","message":{"host":"demo","short_message":"Started","timestamp":1700000000.25,"level":6,"additional_fields":{"service":"api"}}}),log_template: Some(LogTemplate::new().with_info("-> GELF host={message.host} level={message.level} short_message_bytes={message.short_message_len}"))}
}
fn disconnect_action() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".into(),
        description: "Close the GELF transport and command handle".into(),
        parameters: vec![],
        example: json!({"type":"disconnect"}),
        log_template: Some(LogTemplate::new().with_info("-> GELF disconnect")),
    }
}
pub static GELF_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "gelf_connected",
        "GELF emitter transport ready; neither UDP nor TCP has per-message acknowledgment.",
        send_action().example,
    )
    .with_parameters(vec![
        parameter(
            "remote_addr",
            "string",
            "Remote IP and port of the GELF collector",
            true,
        ),
        parameter(
            "local_addr",
            "string",
            "Local IP and port of this GELF emitter",
            true,
        ),
        parameter(
            "transport",
            "string",
            "Selected GELF transport: udp or tcp",
            true,
        ),
    ])
    .with_actions(vec![send_action(), disconnect_action()])
});
impl Protocol for GelfClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "GELF"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP|TCP>GELF"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["gelf", "graylog"]
    }
    fn description(&self) -> &'static str {
        "Emit GELF 1.1 structured logs over UDP or TCP"
    }
    fn example_prompt(&self) -> &'static str {
        "Send a GELF log to localhost:12201"
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![send_action(), disconnect_action()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![GELF_CONNECTED_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![transport_parameter(),ParameterDefinition{name:"compression".into(),type_hint:"string".into(),description:"auto chooses UDP gzip/TCP none; none, gzip or zlib. Explicit TCP compression is rejected.".into(),required:false,example:json!("zlib"),default:Some(json!(DEFAULT_COMPRESSION))},ParameterDefinition{name:"chunk_size".into(),type_hint:"number".into(),description:"UDP datagram size, including 12-byte chunk header; 13..8192. TCP ignores this validated setting.".into(),required:false,example:json!(1420),default:Some(json!(DEFAULT_CHUNK_SIZE))}]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).well_known_udp_port(12201).implementation("Native GELF JSON encoder, bounded UDP compression/chunks and TCP NUL frames").llm_control("Connected event with standard memory updates, typed send action and live command injection").e2e_testing("Both transports and independent official Graylog go-gelf UDP/TCP readers; pygelf emitters in server tests").notes("256KiB message, 128 UDP chunks, 10s connect/write deadline. No TLS, HTTP, acknowledgments, storage or retry; transport success is not end-to-end delivery.").history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_client","base_stack":"gelf","remote_addr":"localhost:12201","instruction":"Send an informational startup log"}),
            json!({"type":"open_client","base_stack":"gelf","remote_addr":"localhost:12201","event_handlers":[{"event_pattern":"gelf_connected","handler":{"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'send_gelf_message','message':{'host':'demo','short_message':'Started'}}]}))"}}]}),
            json!({"type":"open_client","base_stack":"gelf","remote_addr":"localhost:12201","startup_params":{"transport":"tcp"},"event_handlers":[{"event_pattern":"gelf_connected","handler":{"type":"static","actions":[send_action().example]}}]}),
        )
    }
}
impl Client for GelfClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::GelfClient::connect(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match action["type"].as_str() {
            Some("send_gelf_message") => {
                let message: Message = serde_json::from_value(
                    action.get("message").context("missing message")?.clone(),
                )?;
                codec::encode_json(&message)?;
                Ok(ClientActionResult::Custom {
                    name: "send_gelf_message".into(),
                    data: serde_json::to_value(message)?,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("unknown GELF emitter action"),
        }
    }
}

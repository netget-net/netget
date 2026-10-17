use super::codec::{DEFAULT_LLM_FALLBACK, DEFAULT_TRANSPORT, MAX_MESSAGE_BYTES};
use crate::llm::actions::{
    protocol_trait::{ActionResult, Protocol, Server},
    ActionDefinition, Parameter, ParameterDefinition, StartupExamples,
};
use crate::protocol::log_template::LogTemplate;
use crate::protocol::{
    metadata::{DevelopmentState, ProtocolMetadataV2},
    EventType, SpawnContext,
};
use crate::state::app_state::AppState;
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct GelfProtocol;
impl GelfProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn parameter(name: &str, type_hint: &str, description: &str, required: bool) -> Parameter {
    Parameter {
        name: name.into(),
        type_hint: type_hint.into(),
        description: description.into(),
        required,
    }
}
pub fn transport_parameter() -> ParameterDefinition {
    ParameterDefinition {name:"transport".into(),type_hint:"string".into(),description:"udp (default) or tcp. TCP uses uncompressed NUL-delimited JSON; UDP accepts JSON, gzip/zlib and chunks.".into(),required:false,example:json!("tcp"),default:Some(json!(DEFAULT_TRANSPORT))}
}
fn collect_action() -> ActionDefinition {
    ActionDefinition {name:"collect_gelf_message".into(),description:"Observe one validated GELF message in the bounded access log. No persistence or reply traffic.".into(),parameters:vec![],example:json!({"type":"collect_gelf_message"}),log_template: Some(LogTemplate::new().with_info("GELF message observed"))}
}
pub static GELF_MESSAGE_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("gelf_message","One validated GELF 1.1 message after TCP framing or UDP reassembly/decompression. Missing timestamp resolves to receiver time; missing level resolves to ALERT (1). Unmatched events collect without model calls by default.",collect_action().example)
.with_parameters(vec![parameter("message","object","Structured host, short_message, optional full_message, timestamp, level, deprecated facility/file/line, and additional_fields with unprefixed names and string/number values.",true),parameter("source_addr","string","Remote IP and port of the GELF emitter",true),parameter("transport","string","Selected GELF transport: udp or tcp",true)])
.with_actions(vec![collect_action()])
});
impl Protocol for GelfProtocol {
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
        "GELF 1.1 UDP/TCP structured log collector; no model calls by default"
    }
    fn example_prompt(&self) -> &'static str {
        "Collect GELF logs on UDP port 12201"
    }
    fn group_name(&self) -> &'static str {
        "Network Services"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![collect_action()]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![GELF_MESSAGE_EVENT.clone()]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().request_only("GELF is a one-way log stream; collecting a received message has no reply or unsolicited server-message operation.").deliberately_silent().state(DevelopmentState::Experimental).well_known_udp_port(12201).max_inbound_bytes(MAX_MESSAGE_BYTES)
 .implementation("Native bounded GELF 1.1 JSON, UDP chunks/gzip/zlib and NUL-delimited TCP; flate2 compression")
 .llm_control("Explicit static/script/manual/model handlers; llm_fallback=false collects unmatched messages without model calls")
 .e2e_testing("Codec bounds/negative cases, both transports, lifecycle and independent pygelf emitter / official Graylog go-gelf readers")
 .notes("256KiB JSON/compressed message, 8192-byte datagrams, 128 chunks within 5s, 128 pending messages/4MiB payload plus bounded metadata/recent IDs, 256 TCP peers, 30s absolute frame deadline. No TLS, HTTP input, authentication, persistence, acknowledgment or retry. No Stable/fuzz/pcap or complete Graylog platform claim. Metadata is not connectionless because TCP sessions and UDP reassembly must remain live.").history(crate::protocol::metadata::HistoryMode::Off)
 .batching(crate::protocol::metadata::BatchingMode::Unsupported)
 .build()
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![
            transport_parameter(),
            ParameterDefinition {
                name: "llm_fallback".into(),
                type_hint: "boolean".into(),
                description:
                    "Opt unmatched messages into the model; configured handlers always run.".into(),
                required: false,
                example: json!(true),
                default: Some(json!(DEFAULT_LLM_FALLBACK)),
            },
        ]
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_server","base_stack":"gelf","port":12201,"startup_params":{"llm_fallback":true},"instruction":"Summarize suspicious messages"}),
            json!({"type":"open_server","base_stack":"gelf","port":12201,"event_handlers":[{"event_pattern":"gelf_message","handler":{"type":"script","language":"python","code":"import json,sys\njson.load(sys.stdin)\nprint(json.dumps({'actions':[{'type':'collect_gelf_message'}]}))"}}]}),
            json!({"type":"open_server","base_stack":"gelf","port":12201,"startup_params":{"transport":"tcp"},"event_handlers":[{"event_pattern":"gelf_message","handler":{"type":"static","actions":[{"type":"collect_gelf_message"}]}}]}),
        )
    }
}
impl Server for GelfProtocol {
    fn spawn(
        &self,
        ctx: SpawnContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::GelfServer::spawn(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ActionResult> {
        match action["type"].as_str() {
            Some("collect_gelf_message") => Ok(ActionResult::NoAction),
            _ => bail!("unknown GELF collector action"),
        }
    }
}

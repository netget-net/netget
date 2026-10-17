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
use crate::server::ipfix::{
    actions::{duration_parameter, parameter},
    codec::{self, Batch},
};
use crate::state::app_state::AppState;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::sync::LazyLock;
#[derive(Default)]
pub struct IpfixClientProtocol;
impl IpfixClientProtocol {
    pub fn new() -> Self {
        Self
    }
}
pub fn example_batch() -> Value {
    json!({"observation_domain_id":42,"templates":[{"id":256,"fields":[{"element":"source_ipv4_address"},{"element":"destination_ipv4_address"},{"element":"packet_delta_count"}]}],"data_sets":[{"template_id":256,"records":[[{"kind":"ipv4","value":"192.0.2.1"},{"kind":"ipv4","value":"198.51.100.2"},{"kind":"unsigned","value":5}]]}]})
}
fn send() -> ActionDefinition {
    ActionDefinition{name:"export_ipfix_records".into(),description:"Validate one complete typed UDP message before emitting. Each batch repeats all referenced templates; domain sequence advances by locally sent data/options records. No acknowledgment or automatic data retry.".into(),parameters:vec![parameter("batch","object","observation_domain_id;optional unsigned32 export_time;1..32 templates(id>=256,optional scope_count,ordered fields with supported element and optional length);ordered data_sets(template_id,records of aligned typed field values). Kinds unsigned/ipv4/ipv6/string/timestamp_seconds/timestamp_milliseconds. Bounds8192bytes,64sets,256records,32fields,1024byte strings; reduced unsigned sizes1..native width; strings fixed1..1024 or variable65535.",true)],example:json!({"type":"export_ipfix_records","batch":example_batch()}),log_template:Some(LogTemplate::new().with_info("Export a validated IPFIX batch"))}
}
fn disconnect() -> ActionDefinition {
    ActionDefinition {
        name: "disconnect".into(),
        description: "Cancel UDP sends, template refresh, handlers and command handle".into(),
        parameters: vec![],
        example: json!({"type":"disconnect"}),
        log_template: Some(LogTemplate::new().with_info("Disconnect IPFIX exporter")),
    }
}
pub static IPFIX_CONNECTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new(
        "ipfix_connected",
        "UDP exporter ready; collector reception is unconfirmed.",
        send().example,
    )
    .with_parameters(vec![
        parameter(
            "remote_addr",
            "string",
            "Remote IPFIX collector socket address",
            true,
        ),
        parameter("local_addr", "string", "Exporter UDP socket", true),
    ])
    .with_actions(vec![send(), disconnect()])
});
pub static IPFIX_EXPORTED_EVENT: LazyLock<EventType> = LazyLock::new(|| {
    EventType::new("ipfix_exported","One datagram accepted by the local UDP transport, not an end-to-end receipt or persistence acknowledgment.",send().example).with_parameters(vec![parameter("observation_domain_id","number","Exporter observation domain identifier",true),parameter("sequence_number","number","Header sequence before increment",true),parameter("record_count","number","Data/options records",true),parameter("template_count","number","Number of templates in this datagram",true),parameter("byte_count","number","Datagram length",true),parameter("local_transport_only","boolean","True when the local UDP transport accepted this datagram",true)]).with_actions(vec![send(),disconnect()])
});
impl Protocol for IpfixClientProtocol {
    fn protocol_name(&self) -> &'static str {
        "IPFIX"
    }
    fn stack_name(&self) -> &'static str {
        "ETH>IP>UDP>IPFIX"
    }
    fn keywords(&self) -> Vec<&'static str> {
        vec!["ipfix", "ipfix-udp"]
    }
    fn description(&self) -> &'static str {
        "Typed UDP IPFIX exporter with template refresh and per-domain sequence"
    }
    fn example_prompt(&self) -> &'static str {
        "Export IPFIX records to localhost:4739"
    }
    fn group_name(&self) -> &'static str {
        "Network Management"
    }
    fn get_async_actions(&self, _: &AppState) -> Vec<ActionDefinition> {
        vec![send(), disconnect()]
    }
    fn get_sync_actions(&self) -> Vec<ActionDefinition> {
        vec![]
    }
    fn get_event_types(&self) -> Vec<EventType> {
        vec![IPFIX_CONNECTED_EVENT.clone(), IPFIX_EXPORTED_EVENT.clone()]
    }
    fn get_startup_parameters(&self) -> Vec<ParameterDefinition> {
        vec![duration_parameter("template_refresh_seconds",super::transport::DEFAULT_REFRESH_SECONDS,"Periodic active-template retransmission,1..3600seconds; every record batch also repeats its templates")]
    }
    fn metadata(&self) -> ProtocolMetadataV2 {
        ProtocolMetadataV2::builder().state(DevelopmentState::Experimental).well_known_udp_port(4739).implementation("Native typed RFC7011 UDP template/options/data encoder; owned periodic template retransmission").llm_control("Connected/local-export events with standard shared memory, bounded followups and injection independent of parked handlers").e2e_testing("Pinned independent Python IPFIX0.9.7 decoder plus live official GoFlow2 2.2.7 collector; native pair, malformed/atomic bounds and cancellation").notes("UDP-only Experimental subset; no SCTP/TCP/TLS/DTLS, authentication, full information-model, flow store, ACK, durability or data retry.8192bytes/message,64sets,256records,32fields,1024byte strings;32domains,32templates/domain. All referenced templates supplied with every batch; identical definitions refresh and template ID redefinition rejected until a new logical socket. Periodic template-only sends default60s, configurable1..3600s; domain sequence counts locally emitted data/options records modulo2^32.10s resolve/send deadline, one in-flight send;32queued events/actions, followup depth8. Transport acceptance is not collector reception. No fuzz/pcap claim.").history(crate::protocol::metadata::HistoryMode::Last(crate::protocol::metadata::SESSION_HISTORY_ENTRIES))
        .batching(crate::protocol::metadata::BatchingMode::Unsupported)
        .build()
    }
    fn get_startup_examples(&self) -> StartupExamples {
        StartupExamples::new(
            json!({"type":"open_client","base_stack":"ipfix","remote_addr":"localhost:4739","instruction":"Export a flow record"}),
            json!({"type":"open_client","base_stack":"ipfix","remote_addr":"localhost:4739","event_handlers":[{"event_pattern":"ipfix_connected","handler":{"type":"script","language":"python","code":format!("import json,sys\njson.load(sys.stdin)\nprint({:?})",json!({"actions":[send().example]}).to_string())}}]}),
            json!({"type":"open_client","base_stack":"ipfix","remote_addr":"localhost:4739","event_handlers":[{"event_pattern":"ipfix_connected","handler":{"type":"static","actions":[send().example]}}]}),
        )
    }
}
impl Client for IpfixClientProtocol {
    fn connect(
        &self,
        ctx: ConnectContext,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<std::net::SocketAddr>> + Send>>
    {
        Box::pin(super::IpfixClient::connect(ctx))
    }
    fn execute_action(&self, action: Value) -> Result<ClientActionResult> {
        match action["type"].as_str() {
            Some("export_ipfix_records") => {
                let batch: Batch =
                    serde_json::from_value(action.get("batch").context("missing batch")?.clone())?;
                codec::encode(&batch, 0, batch.export_time.unwrap_or(0))?;
                Ok(ClientActionResult::Custom {
                    name: "export_ipfix_records".into(),
                    data: serde_json::to_value(batch)?,
                })
            }
            Some("disconnect") => Ok(ClientActionResult::Disconnect),
            _ => bail!("unknown IPFIX exporter action"),
        }
    }
}
